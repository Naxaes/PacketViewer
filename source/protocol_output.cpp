#define COLOR_BLACK   "\u001b[30m"
#define COLOR_RED     "\u001b[31m"
#define COLOR_GREEN   "\u001b[32m"
#define COLOR_YELLOW  "\u001b[33m"
#define COLOR_BLUE    "\u001b[34m"
#define COLOR_MAGENTA "\u001b[35m"
#define COLOR_CYAN    "\u001b[36m"
#define COLOR_WHITE   "\u001b[37m"
#define COLOR_RESET   "\u001b[0m"


static char ethernet_color[] = COLOR_RED;
static char arp_color[]      = COLOR_GREEN;
static char ipv4_color[]     = COLOR_YELLOW;
static char ipv6_color[]     = COLOR_BLUE;
static char tcp_color[]      = COLOR_MAGENTA;
static char udp_color[]      = COLOR_CYAN;
static char payload_color[]  = COLOR_WHITE;



static char const * const ETHERNET_STRING_TEMPLATE = \
    "| - %sEthernet%s\n";

static char const * const VERBOSE_ETHERNET_STRING_TEMPLATE = \
    "| - %sEthernet%s\n"               
    "|       MAC Destination     : %s\n"
    "|       MAC Source          : %s\n"
    "|       Payload Protocol    : %s\n";

static char const * const ARP_STRING_TEMPLATE = \
    "| - %sARP%s (limited support)\n";

static char const * const VERBOSE_ARP_STRING_TEMPLATE = \
    "| - %sARP%s (limited support)\n";

static char const * const IPv6_STRING_TEMPLATE = \
    "| - %sIPv6%s (not supported)\n";

static char const * const VERBOSE_IPv6_STRING_TEMPLATE = \
    "| - %sIPv6%s (not supported)\n";

static char const * const IPv4_STRING_TEMPLATE = \
    "| - %sIPv4%s \n";

static char const * const VERBOSE_IPv4_STRING_TEMPLATE = \
    "| - %sIPv4%s \n"
    "|       Version             : %u\n"
    "|       Header Length       : %u (32-bit words)\n"
    "|       Precedence          : %u\n"
    "|       Delay               : %u\n"
    "|       Througput           : %u\n"
    "|       Reliability         : %u\n"
    "|       Reserved            : %u\n"
    "|       Total Length        : %u (header + data)\n"
    "|       Identification      : %u\n"
    "|       Reserved            : %u\n"
    "|       DF-flag             : %u\n"
    "|       MF-flag             : %u\n"
    "|       Fragment Offset     : %u (bytes)\n"
    "|       Time To Live (TTT)  : %u\n"
    "|       Payload Protocol    : %s\n"
    "|       Header Checksum     : %u\n"
    "|       Source Addresss     : %s\n"
    "|       Destination Address : %s\n";

static char const * const TCP_STRING_TEMPLATE = \
    "| - %sTCP%s \n";

static char const * const VERBOSE_TCP_STRING_TEMPLATE = \
    "| - %sTCP%s \n"
    "|       Source Port         : %u\n"
    "|       Destination Port    : %u\n"
    "|       SEQ Number          : %u\n"
    "|       ACK Number          : %u\n"
    "|       Data Offset         : %u (32-bit words)\n"
    "|       Reserved            : %u\n"
    "|       NS-flag             : %u\n"
    "|       CWR-flag            : %u\n"
    "|       ECE-flag            : %u\n"
    "|       URG-flag            : %u\n"
    "|       ACK-flag            : %u\n"
    "|       PSH-flag            : %u\n"
    "|       RST-flag            : %u\n"
    "|       SYN-flag            : %u\n"
    "|       FIN-flag            : %u\n"
    "|       Window Size         : %u (bytes)\n"
    "|       Checksum            : %u\n"
    "|       Urgent Pointer      : %u\n";

static char const * const TCP_OPTION_HEADER_STRING_TEMPLATE = \
    "|       Options             : %zu bytes\n";

static char const * const TCP_OPTION_ENTRY_STRING_TEMPLATE = \
    "|           * %-14s: %s (in hex)\n";  // Name and Hex value.


static char const * const UDP_STRING_TEMPLATE = \
    "| - %sUDP%s \n";

static char const * const VERBOSE_UDP_STRING_TEMPLATE = \
    "| - %sUDP%s \n"
    "|       Source Port         : %u\n"
    "|       Destination Port    : %u\n"
    "|       Length              : %u\n"
    "|       Checksum            : %u\n";

static char const * const PAYLOAD_STRING_TEMPLATE = \
    "| - %sPayload%s \n";

static char const * const UNKNOWN_STRING_TEMPLATE = \
    "| - Unknown Protocol %04X\n";



// ---- PRIVATE FUNCTION ----
Buffer FormatBufferForPrinting(const Buffer payload);


char* BinaryFormat(uint16_t value, uint8_t count = 16)
{
    static char buffer[17] = { 0 };

    count = count > 16 ? 16 : count;

    uint16_t i = 0;
    for (; i < count; ++i)
    {
        buffer[i] = bool(value & ((0b1000000000000000) >> i)) ? '1' : '0';
    }
    buffer[i] = '\0';

    return buffer;
}
char* BinaryFormat(uint8_t value, uint8_t count = 8)
{
    count = count > 8 ? 8 : count;
    return BinaryFormat((uint16_t) value, count);
}

char* HexFormat(uint8_t const * const value, uint8_t count)
{
    static char buffer[255] = { 0 };
    uint8_t const size_per_value = 3;  // 2 numbers + 1 space.

    size_t i = 0;
    for (; i < count; ++i)
    {
        snprintf(buffer + (size_per_value * i), size_per_value + 1, "%02X ", value[i]);
    }
    buffer[(size_per_value * i)] = '\0';

    return buffer;
}
char* HexFormat(uint64_t value)
{
    static char buffer[5] = { 0 };
    snprintf(buffer, 5, "%04llX", value);
    return buffer;
}
char* HexFormat(uint32_t value)
{
    return HexFormat((uint64_t) value);
}
char* HexFormat(uint16_t value)
{
    return HexFormat((uint32_t) value);
}
char* HexFormat(uint8_t value)
{
    return HexFormat((uint16_t) value);
}



void Output(const Ethernet* header, FILE* file = stdout)
{
    fprintf(file, ETHERNET_STRING_TEMPLATE, ethernet_color, COLOR_RESET);
}
void OutputVerbose(const Ethernet* header, FILE* file = stdout)
{
    static const size_t mac_address_size = sizeof("00:00:00:00:00:00");
    char mac_dest_buffer[mac_address_size];
    char mac_src_buffer[mac_address_size];

    MacAddressToString(header->destination_mac_address, mac_dest_buffer, mac_address_size);
    MacAddressToString(header->source_mac_address,      mac_src_buffer,  mac_address_size);

    fprintf(file, VERBOSE_ETHERNET_STRING_TEMPLATE, ethernet_color, COLOR_RESET, mac_dest_buffer, mac_src_buffer, ProtocolToString(header->protocol));
}


void Output(const ARP* header, FILE* file = stdout)
{
    fprintf(file, ARP_STRING_TEMPLATE, arp_color, COLOR_RESET);
}

void Output(const IPv6* header, FILE* file = stdout)
{
    fprintf(file, IPv6_STRING_TEMPLATE, ipv6_color, COLOR_RESET);
}

void Output(const IPv4* header, FILE* file = stdout)
{
    fprintf(file, IPv4_STRING_TEMPLATE, ipv4_color, COLOR_RESET);
}
void OutputVerbose(const IPv4* header, FILE* file = stdout)
{
    static const size_t ipv4_address_size = sizeof("255.255.255.255");
    char ipv4_dest_buffer[ipv4_address_size];
    char ipv4_src_buffer[ipv4_address_size];

    IPv4AddressToString(header->source_address,      ipv4_src_buffer,  ipv4_address_size);
    IPv4AddressToString(header->destination_address, ipv4_dest_buffer, ipv4_address_size);

    fprintf(file, VERBOSE_IPv4_STRING_TEMPLATE, ipv4_color, COLOR_RESET, header->version, 
        header->header_length, header->precedence, header->delay, header->througput, 
        header->reliability, header->reserved1, header->total_length, header->identification, 
        header->reserved2, header->DF, header->MF, header->fragment_offset, header->time_to_live, 
        ProtocolToString(header->protocol), header->header_checksum, ipv4_src_buffer, ipv4_dest_buffer
    );

}

void Output(const TCP* header, FILE* file = stdout)
{
    fprintf(file, TCP_STRING_TEMPLATE, tcp_color, COLOR_RESET);
}
void OutputVerbose(const TCP* header, FILE* file = stdout)
{
    fprintf(file, VERBOSE_TCP_STRING_TEMPLATE, tcp_color, COLOR_RESET, header->source_port, 
        header->destination_port, header->sequence_number, header->acknowledgment_number, 
        header->data_offset, header->reserved, header->flag_ns, header->flag_cwr, 
        header->flag_ece, header->flag_urg, header->flag_ack, header->flag_psh, 
        header->flag_rst, header->flag_syn, header->flag_fin, header->window_size, 
        header->checksum, header->urgent
    );

    Buffer options = GetOptions(header);
    if (options.size == 0)
        return;
    
    fprintf(file, TCP_OPTION_HEADER_STRING_TEMPLATE, options.size);

    size_t i = 0;
    while (i < options.size)
    {
        OptionInfo option_info = NextOptionInfo(options.data + i);

        fprintf(file, TCP_OPTION_ENTRY_STRING_TEMPLATE, option_info.printable_name, HexFormat(&options.data[i], option_info.to_advance));

        i += option_info.to_advance;
    }
}

void Output(const UDP* header, FILE* file = stdout)
{
    fprintf(file, UDP_STRING_TEMPLATE, udp_color, COLOR_RESET);
}
void OutputVerbose(const UDP* header, FILE* file = stdout)
{
    fprintf(file, VERBOSE_UDP_STRING_TEMPLATE, udp_color, COLOR_RESET, header->source_port, 
        header->destination_port, header->length, header->checksum
    );
}


void Output(const Buffer header, FILE* file = stdout)
{
    fprintf(file, PAYLOAD_STRING_TEMPLATE, payload_color, COLOR_RESET);
}
void OutputVerbose(const Buffer header, FILE* file = stdout)
{
    Buffer formatted_buffer = FormatBufferForPrinting(header);
    fprintf(file, PAYLOAD_STRING_TEMPLATE, payload_color, COLOR_RESET);
    fprintf(file, "\t%.*s\n", (int)formatted_buffer.size, formatted_buffer.data);
}


void OutputUnknownProtocol(uint16_t protocol, FILE* file = stdout)
{
    fprintf(file, UNKNOWN_STRING_TEMPLATE, protocol);
}
void OutputUnknownProtocol(uint8_t protocol, FILE* file = stdout)
{
    fprintf(file, UNKNOWN_STRING_TEMPLATE, protocol);
}


void OutputPacketInRawHex(Ethernet const * start, size_t end, size_t characters_per_row = 16, FILE* file = stdout)
{
    ASSERT(end < Ethernet::MAX_TOTAL_SIZE, "Packet (%zu bytes) bigger than maximum ethernet size (%u).", end, Ethernet::MAX_TOTAL_SIZE);

    uint32_t line  = 0;
    uint32_t character_on_current_line = 0;
    const uint8_t* base  = (const uint8_t *) start;

    fprintf(file, "%u\t", line++);

    for (uint32_t i = 0; i < end; ++i)
    {
        fprintf(file, "%02X ", base[i]);

        if (character_on_current_line == 7)  // Seperate in bytes by small space.
            fprintf(file, "  ");

        if (character_on_current_line >= characters_per_row - 1 && i < end)
        {
            fprintf(file, "\n%u\t", line++);
            character_on_current_line = 0;
        }
        else
        {
            ++character_on_current_line;
        }
    }
    fprintf(file, "%s\n", COLOR_RESET);
}


// Such hardcoding... But it works!
void OutputPacketInHex(Ethernet const * const ethernet, FILE* file = stdout)
{
    uint8_t * pointer = (uint8_t *) calloc(1, sizeof(Ethernet));
    ethernet->ReadAsByteArray(pointer);

    fprintf(file, 
        "1.\t%s%02X %02X %02X %02X %02X %02X %02X %02X   %02X %02X %02X %02X %02X %02X %s", ethernet_color, 
        pointer[0], pointer[1], pointer[2],  pointer[3],  pointer[4],  pointer[5], pointer[6], pointer[7],
        pointer[8], pointer[9], pointer[10], pointer[11], pointer[12], pointer[13],
        COLOR_RESET
    );

    if (ethernet->protocol == NETWORK_PROTOCOL_IPv4)
    {
        IPv4* ipv4_header = (IPv4 *) NextHeader(ethernet);
        pointer = (uint8_t *) calloc(1, HeaderSize(ipv4_header));
        ipv4_header->ReadAsByteArray(pointer);

        fprintf(file, 
            "%s%02X %02X\n%s2.%s\t%02X %02X %02X %02X %02X %02X %02X %02X   %02X %02X %02X %02X %02X %02X %02X %02X\n%s3.%s\t%02X %02X %s", ipv4_color, 
            pointer[0],  pointer[1],  COLOR_RESET, ipv4_color,  pointer[2],  pointer[3],  pointer[4],  pointer[5],  pointer[6],  pointer[7],
            pointer[8],  pointer[9],  pointer[10], pointer[11], pointer[12], pointer[13], pointer[14], pointer[15],
            pointer[16], pointer[17], COLOR_RESET, ipv4_color,  pointer[18], pointer[19],
            COLOR_RESET
        );
        // TODO(ted): We might want to support IPv4 options.

        if (ipv4_header->protocol == TRANSPORT_PROTOCOL_TCP)
        {
            TCP const * tcp_header = (TCP *) NextHeader(ipv4_header);
            pointer = (uint8_t *) calloc(1, HeaderSize(tcp_header));
            tcp_header->ReadAsByteArray(pointer);

            fprintf(file, 
                "%s%02X %02X %02X %02X %02X %02X   %02X %02X %02X %02X %02X %02X %02X %02X\n%s4.%s\t%02X %02X %02X %02X %02X %02X ", tcp_color, 
                pointer[0],  pointer[1],  pointer[2],  pointer[3],  pointer[4],  pointer[5],  pointer[6],  pointer[7],
                pointer[8],  pointer[9],  pointer[10], pointer[11], pointer[12], pointer[13], COLOR_RESET, tcp_color,  pointer[14], pointer[15],
                pointer[16], pointer[17], pointer[18], pointer[19]
            );

            Buffer options = GetOptions(tcp_header);
            if (options.size == 0)
                return;

            size_t current_line = 5;
            if (options.size > 0)
            {
                for (size_t i = 0; i < options.size; ++i)
                {
                    if (i == 2 || i == 18 || i == 34)
                        fprintf(file, "  %02X ", options.data[i]);
                    else if (i == 10 || i == 26)
                        fprintf(file, "\n%s%zu.%s\t%02X ", COLOR_RESET, current_line++, tcp_color, options.data[i]);
                    else
                        fprintf(file, "%02X ", options.data[i]);
                }
            }

            uint8_t* payload = NextHeader(tcp_header);
            size_t   size    = ipv4_header->total_length - HeaderSize(ipv4_header) - HeaderSize(tcp_header);

            if (size > 0)
            {
                fprintf(file, "%s", payload_color);

                for (size_t i = 0; i < size; ++i)
                {
                    if ((i + 10) % 16 == 0)
                        fprintf(file, "  %02X ", payload[i]);
                    else if ((i + 2) % 16 == 0)
                        fprintf(file, "\n%s%zu.%s\t%02X ", COLOR_RESET, current_line++, payload_color, payload[i]);
                    else
                        fprintf(file, "%02X ", payload[i]);
                }
            }
        }
        else if (ipv4_header->protocol == TRANSPORT_PROTOCOL_UDP)
        {
            UDP* udp_header = (UDP *) NextHeader(ipv4_header);
            pointer = (uint8_t *) calloc(1, HeaderSize(udp_header));
            udp_header->ReadAsByteArray(pointer);

            fprintf(file, 
                "%s%02X %02X %02X %02X %02X %02X   %02X %02X ", udp_color, 
                pointer[0],  pointer[1],  pointer[2],  pointer[3],  pointer[4],  pointer[5],  pointer[6],  pointer[7]
            );

            size_t current_line = 4;

            uint8_t* payload = NextHeader(udp_header);
            size_t   size    = ipv4_header->total_length - HeaderSize(ipv4_header) - HeaderSize(udp_header);

            if (size > 0)
            {
                fprintf(file, "%s", payload_color);

                for (size_t i = 0; i < size; ++i)
                {
                    if ((i + 10) % 16 == 0)
                        fprintf(file, "\n%s%zu.%s\t%02X ", COLOR_RESET, current_line++, payload_color, payload[i]);
                    else if ((i + 2) % 16 == 0)
                        fprintf(file, "  %02X ", payload[i]);
                    else
                        fprintf(file, "%02X ", payload[i]);
                }
            }
        }
        else
        {
           
        }
    }
    else if (ethernet->protocol == NETWORK_PROTOCOL_ARP)
    {
        ARP* arp_header = (ARP *) NextHeader(ethernet);
        uint8_t const * pointer = (uint8_t const *) arp_header;

        fprintf(file, 
            "%s%02X %02X\n%s2.%s\t%02X %02X %02X %02X %02X %02X %02X %02X   %02X %02X %02X %02X %02X %02X %02X %02X\n%s3.%s\t%02X %02X %02X %02X %02X %02X ", arp_color, 
            pointer[0],  pointer[1],  COLOR_RESET, arp_color,   pointer[2],  pointer[3],  pointer[4],  pointer[5],  pointer[6],  pointer[7],
            pointer[8],  pointer[9],  pointer[10], pointer[11], pointer[12], pointer[13], pointer[14], pointer[15],
            pointer[16], pointer[17], COLOR_RESET, arp_color,   pointer[18], pointer[19], pointer[20], pointer[21], pointer[22], pointer[23]
        );
    }
    else if (ethernet->protocol == NETWORK_PROTOCOL_IPv6)
    {
        
    }
    else
    {
        
    }

    fprintf(file, "%s\n", COLOR_RESET);
}

// ---- PRIVATE FUNCTION ----
// Result has to be used immediately. Not thread-safe. Truncates if message is to large.
Buffer FormatBufferForPrinting(const Buffer payload)
{
    static const size_t maximum_size = 65535;
    static char  buffer[maximum_size];

    ASSERT(payload.size < maximum_size, "Buffer size (%zu bytes) is too large.", payload.size);

    size_t characters_per_line = 64;

    size_t character_on_current_line = 0;
    size_t index = 0;
    for (size_t i = 0; i < payload.size; ++i)
    {
        if (index >= maximum_size)
            break;

        if (character_on_current_line >= 64)
        {
            buffer[index++] = '\n';
            buffer[index++] = '\t';
            character_on_current_line = 0;
        }

        if (payload.data[i] < 32 || payload.data[i] == 127)  // Assuming ASCII
        {
            if (payload.data[i] == '\t')
            {
                buffer[index++] = payload.data[i];
                character_on_current_line += 4;
            }
            else if (payload.data[i] == '\n')
            {
                buffer[index++] = payload.data[i];
                buffer[index++] = '\t';
            }
            else
            {
                buffer[index++] = '.';
                ++character_on_current_line;
            }
        }
        else
        {
            buffer[index++] = payload.data[i];
            ++character_on_current_line;
        }
    }



    return { reinterpret_cast<uint8_t*>(buffer), index };
}

void OutputPacketRecursivelyVerbose(const Ethernet* ethernet, size_t packet_size, size_t packet_count, bool include_binary = false, FILE* file = stdout)
{
    fprintf(file, "-------------------------- PACKET %zu [ size %zu ] --------------------------\n", packet_count, packet_size);

    OutputVerbose(ethernet, file);

    if (ethernet->protocol == NETWORK_PROTOCOL_IPv4)
    {
        IPv4* ipv4_header = (IPv4 *) NextHeader(ethernet);
        OutputVerbose(ipv4_header, file);

        if (ipv4_header->protocol == TRANSPORT_PROTOCOL_TCP)
        {
            TCP* tcp_header = (TCP *) NextHeader(ipv4_header);
            OutputVerbose(tcp_header, file);

            uint8_t* payload = NextHeader(tcp_header);
            size_t   size    = ipv4_header->total_length - HeaderSize(ipv4_header) - HeaderSize(tcp_header);

            if (size > 0)
                OutputVerbose({ payload, size }, file);
        }
        else if (ipv4_header->protocol == TRANSPORT_PROTOCOL_UDP)
        {
            UDP* udp_header = (UDP *) NextHeader(ipv4_header);
            OutputVerbose(udp_header, file);

            uint8_t* payload = NextHeader(udp_header);
            int size = ipv4_header->total_length - HeaderSize(ipv4_header) - HeaderSize(udp_header);

            if (size > 0)
                OutputVerbose({ payload, size_t(size) }, file);
        }
        else
        {
            OutputUnknownProtocol(ipv4_header->protocol, file);
        }
    }
    else if (ethernet->protocol == NETWORK_PROTOCOL_ARP)
    {
        ARP* arp_header = (ARP *) NextHeader(ethernet);
        Output(arp_header);
    }
    else if (ethernet->protocol == NETWORK_PROTOCOL_IPv6)
    {
        IPv6* ipv6_header = (IPv6 *) NextHeader(ethernet);
        Output(ipv6_header);
    }
    else
    {
        OutputUnknownProtocol(ethernet->protocol, file);
    }

    if (include_binary)
    {
        fprintf(file, "\n");
        OutputPacketInHex(ethernet);
    }

    fprintf(file, "------------------------------------------------------------------------\n");
}














