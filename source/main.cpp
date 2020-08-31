#include "error.cpp"

#include <cstdint>
#include <cstdlib>
#include <cstdio>

#include <unistd.h>
#include <fcntl.h>          // open, O_RDWR
#include <cstring>
#include <cerrno>

#include <getopt.h>

#include <sys/types.h>
#include <sys/ioctl.h>      // ioctl
#include <sys/uio.h>

#include <net/if.h>
#include <net/ethernet.h>
#include <net/bpf.h>

#include "protocol_headers.cpp"
#include "protocol_helpers.cpp"
#include "protocol_output.cpp"



// ---- USER API ----
// All structs should have the most common default behaviour when
// set to all zeros.

static char const * const DEFAULT_RULES_PATH = "rules.ted";
static char const * const USAGE_HELP_PATH    = "usage.txt";


//{ "en0" };  // lo0 - loopback, en1 - Wifi.
static const char INTERFACE_EN0[] = "en0";
static const char INTERFACE_EN1[] = "en1";
static const char INTERFACE_LO0[] = "lo0";


// How do we make it easy to specify OR and AND between rules?
struct Rule
{
    enum Action { DISCARD, LOG, ACCEPT };

    enum Item : uint64_t
    {        
        MAC_SRC_ADDRESS,
        MAC_DST_ADDRESS,
        MAC_ADDRESS,
        NETWORK_PROTOCOL,
        TRANSPORT_PROTOCOL,
        IPv4_SRC_ADDRESS,
        IPv4_DST_ADDRESS,
        IPv4_ADDRESS,
        SRC_PORT,
        DST_PORT,
        PORT
    };

    struct Pair
    {
        Item     item;
        uint64_t value;
        Pair*    next = nullptr;  // TODO(ted): Maybe make a std::optional?
    };

    Action action;
    Pair   pair;
};

struct Filter
{
    Rule*  rules;
    size_t count;

    Rule::Action default_action = Rule::DISCARD;
};

struct Options
{
    bool  use_network_endianness = false;
    FILE* log_file = stdout;
};

struct Device
{
    int fd;

    uint8_t* buffer;
    size_t   required_buffer_size;

    uint8_t* packet_pointer;
    uint8_t* end_of_recorded_buffer;
};

struct Packet
{
    uint8_t* buffer;
    size_t   size;
};


Packet ReadPacket(Device& device, Filter filter, Options options, size_t packet_count)
{
    // TODO(ted): Put this if-statement in a new function and allocate new memory for each packet.
    //   That would allow us to put this into a new thread and throw the packets into a queue.
    if (device.packet_pointer >= device.end_of_recorded_buffer)
    {
        // Record another buffer.
        int bytes_read = read(device.fd, device.buffer, device.required_buffer_size);
        if (bytes_read <= 0) 
            return { };

        device.packet_pointer = (uint8_t *) device.buffer;
        device.end_of_recorded_buffer = device.packet_pointer + bytes_read;
    }


    // BPF HEADER
    bpf_hdr const * const bpf_header = (bpf_hdr const * const) device.packet_pointer;
    size_t  const bpf_total_size     = bpf_header->bh_hdrlen + bpf_header->bh_caplen;
    size_t  const bpf_header_size    = bpf_header->bh_hdrlen;
    size_t  const bpf_payload_size   = bpf_header->bh_caplen;


    // EXTRACT HEADERS NEEDED TO FILTER
    Ethernet * const ethernet_header  = (Ethernet * const) (device.packet_pointer + bpf_header_size);                                                      // Move past the bpf header.
    IPv4     * const ipv4_header      = (IPv4     * const) (device.packet_pointer + bpf_header_size + sizeof(Ethernet));                                   // Move to network header.
    uint8_t  * const transport_header = (uint8_t  * const) (device.packet_pointer + bpf_header_size + sizeof(Ethernet) + ipv4_header->header_length * 4);  // Move to transport header.


    // ADVANCE PACKET POINTER
    device.packet_pointer += BPF_WORDALIGN(bpf_total_size);


    // MATCH. NOTE(ted): Everything is still in network endianness.
    for (size_t i = 0; i < filter.count; ++i)
    {
        Rule const rule = filter.rules[i];
        Rule::Pair const * pair = &rule.pair;

        // CHECK IF RULE (AND NESTED RULES) MATCHES.
        bool match = true;
        while (pair != nullptr)
        {
            if      (pair->item == Rule::MAC_SRC_ADDRESS    &&  pair->value == HardwareByteOrder(ethernet_header->source_mac_address)      )  { pair = pair->next; }
            else if (pair->item == Rule::MAC_DST_ADDRESS    &&  pair->value == HardwareByteOrder(ethernet_header->destination_mac_address) )  { pair = pair->next; }
            else if (pair->item == Rule::NETWORK_PROTOCOL   &&  pair->value == HardwareByteOrder(ethernet_header->protocol)                )  { pair = pair->next; }
            else if (pair->item == Rule::TRANSPORT_PROTOCOL &&  pair->value == HardwareByteOrder(ipv4_header->protocol)                    )  { pair = pair->next; }
            else if (pair->item == Rule::IPv4_SRC_ADDRESS   &&  pair->value == HardwareByteOrder(ipv4_header->source_address)              )  { pair = pair->next; }
            else if (pair->item == Rule::IPv4_DST_ADDRESS   &&  pair->value == HardwareByteOrder(ipv4_header->destination_address)         )  { pair = pair->next; }
            else if (pair->item == Rule::SRC_PORT           &&  pair->value == HardwareByteOrder(*(uint16_t *) (transport_header + 0))     )  { pair = pair->next; }
            else if (pair->item == Rule::DST_PORT           &&  pair->value == HardwareByteOrder(*(uint16_t *) (transport_header + 2))     )  { pair = pair->next; }
            else    { match = false; break; }
        }

        // APPLY FIRST RULE THAT MATCHED, I.E. DON'T CONTINUE.
        if (match)
        {
            if (rule.action == Rule::DISCARD)
                return {};

            if (!options.use_network_endianness)
                FormatToHardware(ethernet_header);

            if (rule.action == Rule::LOG)
                OutputPacketRecursivelyVerbose(ethernet_header, bpf_payload_size, packet_count, true, options.log_file);

            if (rule.action == Rule::ACCEPT || rule.action == Rule::LOG)
                return { (uint8_t *) ethernet_header, bpf_payload_size };

            ASSERT(false, "Invalid code path. A new rule might have been added or something else is screwed up!");
        }
    }

    // NO MATCHES. APPLY FILTER DEFAULT ACTION.
    if (filter.default_action == Rule::DISCARD)
        return {};

    if (!options.use_network_endianness)
        FormatToHardware(ethernet_header);

    if (filter.default_action == Rule::LOG)
        OutputPacketRecursivelyVerbose(ethernet_header, bpf_payload_size, packet_count, true, options.log_file);

    if (filter.default_action == Rule::ACCEPT || filter.default_action == Rule::LOG)
        return { (uint8_t *) ethernet_header, bpf_payload_size };

    ASSERT(false, "Invalid code path. A new rule might have been added or something else is screwed up!");
    return {};
}


Device LoadDevice()
{
     // ---- Try open the next available bpf device. ----
    int fd = 0;
    {
        static const uint8_t buffer_size = sizeof("/dev/bpf99");
        char buffer[buffer_size] = { 0 };
        
        for (int i = 0; i < 99; ++i)
        {
            snprintf(buffer, buffer_size, "/dev/bpf%i", i);
            
            fd = open(buffer, O_RDWR);  // Open for reading and writing.
            
            if (fd != -1)
                break;
        }

        if (fd == -1)
            ERROR("Couldn't open any /dev/bpf* device. \n"
                "They are either all busy or protected by a higher permission (try running with sudo).\n");
    }


    // ---- Enable immediate mode and request the buffer size. ----
    size_t        required_buffer_size     =     0;
    uint32_t      data_link_protocol       =     0;
    ifreq         hardware_interface_name  =   { 0 };
    ifreq         bound_if                 = { "en0" };  // lo0 - loopback, en1 - Wifi.
    bpf_version   version                  =   { 0 };
    
    // Bind the descriptor with the interface.
    if (ioctl(fd, BIOCSETIF, &bound_if) == -1)
        ERROR("Call to 'ioctl' failed. Reason: '%s.'.\n"
              "Interface variable '%s' probably doesn't exist.\n", strerror(errno), bound_if.ifr_name
        );

    // Query the required buffer length for reads on bpf files.
    ASSERT(ioctl(fd, BIOCGBLEN, &required_buffer_size) >= 0, "Call to 'ioctl' failed. Reason: '%s.'\n", strerror(errno));

    // TODO(ted): This is not correct if we request an interface as loopback.
    // Make sure the underlying data link layer for the attached interface is Ethernet.
    if (ioctl(fd, BIOCGDLT, &data_link_protocol) == -1)
        ERROR("Call to 'ioctl' failed. Reason: '%s.'\n", strerror(errno));
    if (data_link_protocol != DLT_EN10MB)
        ERROR("This program only supports ethernet connections.\n"
              "Serial Line Internet Protocol (SLIP) or other protocols\n"
              "for the data link layer on the interface is not supported.\n" 
        ); 

    // Force the interface into promiscuous mode.
    uint32_t promiscuous_mode = true;
    ASSERT(ioctl(fd, BIOCPROMISC, &promiscuous_mode) >= 0, "Call to 'ioctl' failed. Reason: '%s.'\n", strerror(errno));

    // Returns the name of the hardware interface.
    ASSERT(ioctl(fd, BIOCGETIF, &hardware_interface_name) >= 0, "Call to 'ioctl' failed. Reason: '%s.'\n", strerror(errno));

    // Return immediately when a packet received (instead of waiting for bpf buffer to be full).
    uint32_t immediate_mode = true;
    ASSERT(ioctl(fd, BIOCIMMEDIATE, &immediate_mode) >= 0, "Call to 'ioctl' failed. Reason: '%s.'\n", strerror(errno));

    ASSERT(ioctl(fd, BIOCVERSION, &version) >= 0, "Call to 'ioctl' failed. Reason: '%s.'\n", strerror(errno));
    ASSERT(BPF_MAJOR_VERSION == version.bv_major && BPF_MINOR_VERSION >= version.bv_minor, "Wrong version. Reason: '%s.'\n", strerror(errno));

    // Allows us to manually fill the MAC source address instead of the kernel.
    uint32_t dont_fill_mac = true;
    ASSERT(ioctl(fd, BIOCSHDRCMPLT, &dont_fill_mac) >= 0, "Call to 'ioctl' failed. Reason: '%s.'\n", strerror(errno));


    return {fd, static_cast<uint8_t*>(malloc(required_buffer_size)), required_buffer_size, nullptr, nullptr };
}

bool ParseArgumentAction(const char* argument, Rule::Action& output)
{
    if (strncmp(argument, "discard", sizeof("discard")-1) == 0 || strncmp(argument, "DISCARD", sizeof("DISCARD")-1) == 0)
    {   
        output = Rule::DISCARD;
        return true;
    }
    if (strncmp(argument, "accept", sizeof("accept")-1) == 0 || strncmp(argument, "ACCEPT", sizeof("ACCEPT")-1) == 0)
    {   
        output = Rule::ACCEPT;
        return true;
    }
    if (strncmp(argument, "log", sizeof("log")-1) == 0 || strncmp(argument, "LOG", sizeof("LOG")-1) == 0)
    {
        output = Rule::LOG;
        return true;
    }
    return false;
}
bool ParseArgumentMacAddress(const char* argument, uint64_t& output)
{
    uint32_t number_1 = 0;
    uint32_t number_2 = 0;
    uint32_t number_3 = 0;
    uint32_t number_4 = 0;
    uint32_t number_5 = 0;
    uint32_t number_6 = 0;

    int count = sscanf(argument, "%2x:%2x:%2x:%2x:%2x:%2x", 
        &number_1, &number_2, &number_3, &number_4, &number_5, &number_6
    );

    if (count != 6)
        return false;

    output = (uint64_t(number_1) << 40) | 
             (uint64_t(number_2) << 32) | 
             (uint64_t(number_3) << 24) | 
             (uint64_t(number_4) << 16) | 
             (uint64_t(number_5) << 8)  | 
             (uint64_t(number_6) << 0);

    return true;
}
bool ParseArgumentNetworkProtocol(const char* argument, uint16_t& output)
{
    if (strncmp(argument, "ipv4", 4) == 0 || strncmp(argument, "IPv4", 4) == 0 || strncmp(argument, "IPV4", 4) == 0)
    {   
        output = NETWORK_PROTOCOL_IPv4;
        return true;
    }
    if (strncmp(argument, "arp", 3) == 0 || strncmp(argument, "ARP", 3) == 0)
    {   
        output = NETWORK_PROTOCOL_ARP;
        return true;
    }
    return false;
}
bool ParseArgumentTransportProtocol(const char* argument, uint8_t& output)
{
    if (strncmp(argument, "udp", 3) == 0 || strncmp(argument, "UDP", 3) == 0)
    {   
        output = TRANSPORT_PROTOCOL_UDP;
        return true;
    }
    if (strncmp(argument, "tcp", 3) == 0 || strncmp(argument, "TCP", 3) == 0)
    {   
        output = TRANSPORT_PROTOCOL_TCP;
        return true;
    }
    return false;
}
bool ParseArgumentIpv4Address(const char* argument, uint32_t& output)
{
    uint8_t number_1 = 0;
    uint8_t number_2 = 0;
    uint8_t number_3 = 0;
    uint8_t number_4 = 0;

    int count = sscanf(argument, "%hhu.%hhu.%hhu.%hhu", 
        &number_1, &number_2, &number_3, &number_4  
    );

    if (count != 4)
        return false;

    output = (uint32_t(number_1) << 24) | 
             (uint32_t(number_2) << 16) | 
             (uint32_t(number_3) << 8)  | 
             (uint32_t(number_4) << 0);

    return true;
}
bool ParseArgumentPort(const char* argument, uint16_t& output)
{
    uint16_t result = 0;
    int count = sscanf(argument, "%hu", &result);
    if (count != 1)
        return false;

    output = result;
    return true;
}


bool ParseArguments(int argc, char * const * argv)
{
    // ---- Get options ----
    static const struct option long_options[] = {
        {"action", required_argument,  0,  'a' },
        {"rule",   no_argument,        0,  'r' },
        {"delete", no_argument,        0,  'd' },
        {"help",   no_argument,        0,  'h' },
        {"show",   no_argument,        0,  's' },

        {"mac-source",         required_argument,  0,  0 },
        {"mac-destination",    required_argument,  0,  1 },
        {"network-protocol",   required_argument,  0,  2 },
        {"transport-protocol", required_argument,  0,  3 },
        {"ipv4-source",        required_argument,  0,  4 },
        {"ipv4-destination",   required_argument,  0,  5 },
        {"port-source",        required_argument,  0,  6 },
        {"port-destination",   required_argument,  0,  7 },
        {0, 0, 0, 0 }
    };

    // RUN THE PROGRAM
    if (argc <= 1)
        return true;

    char  buffer[1024] = { 0 };
    char* pointer = buffer;

    bool rule_attributes_specified = false;
    bool rule_action_specified     = false;
    bool open_file = false;
    
    int option = -1;
    int option_index = 0;
    while ((option = getopt_long(argc, argv, "a:rdhso:", long_options, &option_index)) != -1) 
    {
        switch (option) 
        {
            case 's':
            {
                FILE* file = fopen(DEFAULT_RULES_PATH, "r");
                if (!file)
                {
                    fprintf(stderr, "You have no rule list in your directory.\n");
                    return false;
                }

                char character = fgetc(file); 

                if (character == EOF)
                {
                    fprintf(stderr, "You have no rule list in your directory.\n");
                    return false;
                }

                while (character != EOF) 
                { 
                    fputc(character, stdout); 
                    character = fgetc(file);
                }
                return false;
            } break;
            case 'h':
            {
                FILE* file = fopen(USAGE_HELP_PATH, "r");
                if (!file)
                {
                    fprintf(stderr, "You have no rule list in your directory.\n");
                    return false;
                }

                char character = fgetc(file); 
                while (character != EOF) 
                { 
                    fputc(character, stdout); 
                    character = fgetc(file);
                }
                return false;
            } break;
            case 'd':
            {
                remove(DEFAULT_RULES_PATH);
                return false;
            } break; 
            case 'r':
            {
                open_file = true;
                pointer += sprintf(pointer, "rule ");
            } break;
            case 'a':
            {
                Rule::Action result = {};
                if (!ParseArgumentAction(optarg, result))
                {
                    fprintf(stderr, "Argument %s is has invalid value %s.\n", long_options[option_index].name, optarg);
                    return false;
                }
                pointer += sprintf(pointer, "action %s ", optarg);
                rule_action_specified = true;
            } break;
            case 0:
            {
                uint64_t result = 0;
                if (!ParseArgumentMacAddress(optarg, result))
                {
                    fprintf(stdout, "Argument %s is has invalid value %s.\n", long_options[option_index].name, optarg);
                    return false;
                }
                pointer += sprintf(pointer, "mac-source %s ", optarg);
                rule_attributes_specified = true;
            } break;
            case 1:
            {
                uint64_t result = 0;
                if (!ParseArgumentMacAddress(optarg, result))
                {
                    fprintf(stderr, "Argument %s is has invalid value %s.\n", long_options[option_index].name, optarg);
                    return false;
                }
                pointer += sprintf(pointer, "mac-destination %s ", optarg);
                rule_attributes_specified = true;
            } break;
            case 2:
            {
                uint16_t result = 0;
                if (!ParseArgumentNetworkProtocol(optarg, result))
                {
                    fprintf(stderr, "Argument %s is has invalid value %s.\n", long_options[option_index].name, optarg);
                    return false;
                }
                pointer += sprintf(pointer, "network-protocol %s ", optarg);
                rule_attributes_specified = true;
            } break;
            case 3:
            {
                uint8_t result = 0;
                if (!ParseArgumentTransportProtocol(optarg, result))
                {
                    fprintf(stderr, "Argument %s is has invalid value %s.\n", long_options[option_index].name, optarg);
                    return false;
                }
                pointer += sprintf(pointer, "transport-protocol %s ", optarg);
                rule_attributes_specified = true;
            } break;
            case 4:
            {
                uint32_t result = 0;
                if (!ParseArgumentIpv4Address(optarg, result))
                {
                    fprintf(stderr, "Argument %s is has invalid value %s.\n", long_options[option_index].name, optarg);
                    return false;
                }
                pointer += sprintf(pointer, "ipv4-source %s ", optarg);
                rule_attributes_specified = true;
            } break;
            case 5:
            {
                uint32_t result = 0;
                if (!ParseArgumentIpv4Address(optarg, result))
                {
                    fprintf(stderr, "Argument %s is has invalid value %s.\n", long_options[option_index].name, optarg);
                    return false;
                }
                pointer += sprintf(pointer, "ipv4-destination %s ", optarg);
                rule_attributes_specified = true;
            } break;
            case 6:
            {
                uint16_t result = 0;
                if (!ParseArgumentPort(optarg, result))
                {
                    fprintf(stderr, "Argument %s is has invalid value %s.\n", long_options[option_index].name, optarg);
                    return false;
                }
                pointer += sprintf(pointer, "port-source %s ", optarg);
                rule_attributes_specified = true;
            } break;
            case 7:
            {
                uint16_t result = 0;
                if (!ParseArgumentPort(optarg, result))
                {
                    fprintf(stderr, "Argument %s is has invalid value %s.\n", long_options[option_index].name, optarg);
                    return false;
                }
                pointer += sprintf(pointer, "port-destination %s ", optarg);
                rule_attributes_specified = true;
            } break;
            default:
            {
                fprintf(stderr, "[ERROR %d]\n", option);
                return false;
            }
        }
    }

    if (!open_file)
    {
        fprintf(stderr, "Must specify rule.\n");
        return false;
    }

    if (!rule_attributes_specified)
    {
        fprintf(stderr, "Cannot specify rule without any attributes.\n");
        return false;
    }

    if (!rule_action_specified)
    {
        fprintf(stderr, "Cannot specify rule without an action.\n");
        return false;
    }

    // ADD RULE TO RULE LIST
    FILE* file = fopen("rules.ted", "a");
    if (!file)
    {
        fprintf(stderr, "Couldn't create rules file.\n");
        return false;
    }
    else
    {
        fprintf(file, "%s\n", buffer);
        fclose(file);
    }

    return false;
}



int main(int argc, char* argv[])
{
    bool continue_ = ParseArguments(argc, argv);

    if (!continue_)
        return 1;

    Device device = LoadDevice();

    ASSERT(device.fd != -1, "An error happened...");


    // Currently, filter will apply first rule that matches. In the case below, the second rule will never apply.
    // Rule rules[] = { { Rule::ACCEPT, Rule::NETWORK_PROTOCOL, Ethernet::IPv4 }, { Rule::LOG, Rule::IPv4_DST_ADDRESS, 0xFFFFFFFF } };

    /*
    Rule::Pair to_my_ip_only = { Rule::IPv4_SRC_ADDRESS, StringToIPv4Address("192.168.1.96") };

    Rule rules[] = { 
        { Rule::LOG, { Rule::DST_PORT, 8080,  &to_my_ip_only }  },
        { Rule::LOG, { Rule::DST_PORT, 80,    &to_my_ip_only }  },
        { Rule::LOG, { Rule::DST_PORT, 8008,  &to_my_ip_only }  }
    };


    Filter filter;
    filter.rules = rules;
    filter.count = 3;
    filter.default_action = Rule::LOG;


    Options options;
    options.use_network_endianness = false;
    options.log_file = stdout;
    */


    FILE* file = fopen(DEFAULT_RULES_PATH, "r");
    if (!file)
    {
        fprintf(stderr, "You have no rule list in your directory.\n");
        return 1;
    }

    static size_t const MAX_LINE_LENGTH = 255;
    char buffer[MAX_LINE_LENGTH] = { 0 };
    char* pointer = buffer;


    Rule rules[32] = { };
    uint32_t rule_count = 0;

    while (fgets(pointer, MAX_LINE_LENGTH, file)) 
    {
        if (strncmp(pointer, "rule ", sizeof("rule ")-1) != 0)
        {
            fprintf(stderr, "Invalid rules file!\n");
            return 1;
        }

        pointer += sizeof("rule ")-1;

        Rule::Pair filter_pair[32] = { };
        uint8_t filter_pair_count = 0;
        Rule& rule = rules[rule_count++];

        while (*pointer != '\0' && *pointer != '\n')
        {
            if (strncmp(pointer, "mac-source ", sizeof("mac-source ")-1) == 0)
            {
                pointer += sizeof("mac-source ")-1;
                Rule::Pair& pair = filter_pair[filter_pair_count++];
                pair.item = Rule::MAC_SRC_ADDRESS;
                if (!ParseArgumentMacAddress(pointer, pair.value))
                {
                    ERROR("Couldn't parse value of 'mac-source'.\n"
                          "The syntax in '%s' is wrong.\n"
                          "Try to delete the file using 'ted --delete' and add the rules again.", DEFAULT_RULES_PATH);
                    return 1;
                }
                while (*pointer != ' ' && *pointer != '\n')
                    ++pointer;
                ++pointer;
            }
            else if (strncmp(pointer, "mac-destination ", sizeof("mac-destination ")-1) == 0)
            {
                pointer += sizeof("mac-destination ")-1;
                Rule::Pair& pair = filter_pair[filter_pair_count++];
                pair.item = Rule::MAC_DST_ADDRESS;
                if (!ParseArgumentMacAddress(pointer, pair.value))
                {
                    ERROR("Couldn't parse value of 'mac-destination'.\n"
                          "The syntax in '%s' is wrong.\n"
                          "Try to delete the file using 'ted --delete' and add the rules again.", DEFAULT_RULES_PATH);
                    return 1;
                }
                while (*pointer != ' ' && *pointer != '\n')
                    ++pointer;
                ++pointer;
            }
            else if (strncmp(pointer, "network-protocol ", sizeof("network-protocol ")-1) == 0)
            {
                pointer += sizeof("network-protocol ")-1;
                Rule::Pair& pair = filter_pair[filter_pair_count++];
                pair.item = Rule::NETWORK_PROTOCOL;
                if (!ParseArgumentNetworkProtocol(pointer, *(uint16_t*) &pair.value))
                {
                    ERROR("Couldn't parse value of 'network-protocol'.\n"
                          "The syntax in '%s' is wrong.\n"
                          "Try to delete the file using 'ted --delete' and add the rules again.", DEFAULT_RULES_PATH);
                    return 1;
                }
                while (*pointer != ' ' && *pointer != '\n')
                    ++pointer;
                ++pointer;
            }
            else if (strncmp(pointer, "transport-protocol ", sizeof("transport-protocol ")-1) == 0)
            {
                pointer += sizeof("transport-protocol ")-1;
                Rule::Pair& pair = filter_pair[filter_pair_count++];
                pair.item = Rule::TRANSPORT_PROTOCOL;
                if (!ParseArgumentTransportProtocol(pointer, *(uint8_t*) &pair.value))
                {
                    ERROR("Couldn't parse value of 'transport-protocol'.\n"
                          "The syntax in '%s' is wrong.\n"
                          "Try to delete the file using 'ted --delete' and add the rules again.", DEFAULT_RULES_PATH);
                    return 1;
                }
                while (*pointer != ' ' && *pointer != '\n')
                    ++pointer;
                ++pointer;
            }
            else if (strncmp(pointer, "ipv4-source ", sizeof("ipv4-source ")-1) == 0)
            {
                pointer += sizeof("ipv4-source ")-1;
                Rule::Pair& pair = filter_pair[filter_pair_count++];
                pair.item = Rule::IPv4_SRC_ADDRESS;
                if (!ParseArgumentIpv4Address(pointer, *(uint32_t*) &pair.value))
                {
                    ERROR("Couldn't parse value of 'ipv4-source'.\n"
                          "The syntax in '%s' is wrong.\n"
                          "Try to delete the file using 'ted --delete' and add the rules again.", DEFAULT_RULES_PATH);
                    return 1;
                }
                while (*pointer != ' ' && *pointer != '\n')
                    ++pointer;
                ++pointer;
            }
            else if (strncmp(pointer, "ipv4-destination ", sizeof("ipv4-destination ")-1) == 0)
            {
                pointer += sizeof("ipv4-destination ")-1;
                Rule::Pair& pair = filter_pair[filter_pair_count++];
                pair.item = Rule::IPv4_DST_ADDRESS;
                if (!ParseArgumentIpv4Address(pointer, *(uint32_t*) &pair.value))
                {
                    ERROR("Couldn't parse value of 'ipv4-destination'.\n"
                          "The syntax in '%s' is wrong.\n"
                          "Try to delete the file using 'ted --delete' and add the rules again.", DEFAULT_RULES_PATH);
                    return 1;
                }
                while (*pointer != ' ' && *pointer != '\n')
                    ++pointer;
                ++pointer;
            }
            else if (strncmp(pointer, "port-source ", sizeof("port-source ")-1) == 0)
            {
                pointer += sizeof("port-source ")-1;
                Rule::Pair& pair = filter_pair[filter_pair_count++];
                pair.item = Rule::SRC_PORT;
                if (!ParseArgumentPort(pointer, *(uint16_t*) &pair.value))
                {
                    ERROR("Couldn't parse value of 'port-source'.\n"
                          "The syntax in '%s' is wrong.\n"
                          "Try to delete the file using 'ted --delete' and add the rules again.", DEFAULT_RULES_PATH);
                    return 1;
                }
                while (*pointer != ' ' && *pointer != '\n')
                    ++pointer;
                ++pointer;
            }
            else if (strncmp(pointer, "port-destination ", sizeof("port-destination ")-1) == 0)
            {
                pointer += sizeof("port-destination ")-1;
                Rule::Pair& pair = filter_pair[filter_pair_count++];
                pair.item = Rule::DST_PORT;
                if (!ParseArgumentPort(pointer, *(uint16_t*) &pair.value))
                {
                    ERROR("Couldn't parse value of 'port-destination'.\n"
                          "The syntax in '%s' is wrong.\n"
                          "Try to delete the file using 'ted --delete' and add the rules again.", DEFAULT_RULES_PATH);
                    return 1;
                }
                while (*pointer != ' ' && *pointer != '\n')
                    ++pointer;
                ++pointer;
            }
            else if (strncmp(pointer, "action ", sizeof("action ")-1) == 0)
            {
                pointer += sizeof("action ")-1;
                Rule::Action action = {};
                if (!ParseArgumentAction(pointer, action))
                {
                    ERROR("Couldn't parse value of 'action'.\n"
                          "The syntax in '%s' is wrong.\n"
                          "Try to delete the file using 'ted --delete' and add the rules again.", DEFAULT_RULES_PATH);
                    return 1;
                }
                while (*pointer != ' ' && *pointer != '\n')
                    ++pointer;
                ++pointer;

                rule.action = action;
            }
            else 
            {
                ASSERT(false, "no");
            }  
        }

        ASSERT(filter_pair_count > 0, "no");
        rule.pair = filter_pair[0];

        for (int i = 1; i < filter_pair_count; ++i)
            rule.pair.next = &filter_pair[i];

    }


    Filter filter;
    filter.rules = rules;
    filter.count = rule_count;
    filter.default_action = Rule::DISCARD;


    Options options;
    options.use_network_endianness = false;
    options.log_file = stdout;


    bool running = true;
    size_t packet_count = 0;
    while (running)
    {
        ++packet_count;
        Packet packet = ReadPacket(device, filter, options, packet_count);
    }

    return 0;
}















