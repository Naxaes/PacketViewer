

uint16_t Join(uint8_t a, uint8_t b)
{
    uint16_t result = (uint16_t(a) << 8 ) | 
                      (uint16_t(a) << 0 );

    return result;
}

uint32_t Join(uint8_t a, uint8_t b, uint8_t c, uint8_t d)
{
    uint32_t result = (uint32_t(a) << 24) | 
                      (uint32_t(a) << 16) | 
                      (uint32_t(a) << 8 ) | 
                      (uint32_t(a) << 0 );

    return result;
}



struct Buffer
{
    uint8_t* data;
    size_t   size;
};


size_t HeaderSize(const Ethernet* header) { return sizeof(Ethernet); }
size_t HeaderSize(const IPv4*     header) { return header->header_length * 4; }
size_t HeaderSize(const UDP*      header) { return sizeof(UDP); }
size_t HeaderSize(const TCP*      header) { return header->data_offset   * 4; }


uint8_t* NextHeader(const Ethernet* header)
{
    uint8_t* base = (uint8_t *) (header);
    uint8_t* next = base + HeaderSize(header);
    return next;
}
uint8_t* NextHeader(const IPv4* header)
{
    uint8_t* base = (uint8_t *) (header);
    uint8_t* next = base + HeaderSize(header);
    return next;
}
uint8_t* NextHeader(const UDP* header)
{
    uint8_t* base = (uint8_t *) (header);
    uint8_t* next = base + HeaderSize(header);
    return next;
}
uint8_t* NextHeader(const TCP* header)
{
    uint8_t* base = (uint8_t *) (header);
    uint8_t* next = base + HeaderSize(header);
    return next;
}


size_t GetOptionsSize(const TCP* header)
{
    size_t   size = header->data_offset * 4 - sizeof(TCP);
    return size;
}

Buffer GetOptions(const TCP* header)
{    
    uint8_t* base = (uint8_t *) header;
    uint8_t* data = base + sizeof(TCP);

    size_t size = GetOptionsSize(header);

    return { data, size };
}



static const uint8_t KIND_END_OF_OPTIONS = 0x00;
static const uint8_t KIND_PADDING        = 0x01;
static const uint8_t KIND_MSS            = 0x02;  // Needs SYN
static const uint8_t KIND_WINDOW_SCALE   = 0x03;  // Needs SYN
static const uint8_t KIND_ALLOW_SACK     = 0x04;  // Needs SYN
static const uint8_t KIND_SACK           = 0x05;
static const uint8_t KIND_TIMESTAMP      = 0x08;

struct OptionInfo
{
    const char* printable_name;
    uint8_t to_advance;
};

// TODO(ted): The options buffer must be count in size.
OptionInfo NextOptionInfo(uint8_t* base)
{        
    size_t  i = 0;
    uint8_t kind = base[i++];

    if (kind == KIND_END_OF_OPTIONS)
    {
        return { "End of options", 1 };
    }
    else if (kind == KIND_PADDING)
    {
        return { "No operation", 1 };
    }
    else if (kind == KIND_MSS)
    {
        uint8_t size = base[i++];
        ASSERT(size == 4, "Invalid size (%u) for option KIND_MSS. Should be %u.", size, 4);

        return { "Maximum segment size", size }; 
    }
    else if (kind == KIND_WINDOW_SCALE)
    {
        uint8_t size = base[i++];
        ASSERT(size == 3, "Invalid size (%u) for option KIND_WINDOW_SCALE. Should be %u.", size, 3);

        return { "Window scale", size }; 
    }
    else if (kind == KIND_ALLOW_SACK)
    {
        uint8_t size = base[i++];
        ASSERT(size == 2, "Invalid size (%u) for option KIND_ALLOW_SACK. Should be %u.", size, 2);

        return { "Selective Acknowledgement permitted", size }; 
    }
    else if (kind == KIND_SACK)
    {
        uint8_t size = base[i++];

        ASSERT(size == 10 || size == 18 || size == 26 || size == 34, "Invalid size (%u) for option KIND_SACK. Should be 10, 18, 26, or 34.", size);

        return { "Selective ACKnowledgement", size }; 
    }
    else if (kind == KIND_TIMESTAMP)
    {
        uint8_t size = base[i++];
        ASSERT(size == 10, "Invalid size (%u) for option KIND_TIMESTAMP. Should be %u.", size, 10);

        return { "Timestamp and echo", size };
    }
    else
    {
        ASSERT(false, "Invalid TCP option kind %u. This option is historical, obsolete, experimental, not yet standardized, or unassigned", kind);
        return {};
    }
}



// Have not checked correctness of these yet.
// They are most likely bogus.
uint16_t Checksum(IPv4& header)
{
    /*
    The checksum field is the 16-bit one's complement of the one's complement 
    sum of all 16-bit words in the header. For purposes of computing the 
    checksum, the value of the checksum field is zero.
    */
    ASSERT(header.header_checksum == 0, "Checksum must be set to zero before calculating the checksum.");

    uint8_t* buffer = (uint8_t*) &header;
    uint8_t  number_of_bytes = sizeof(IPv4);

    uint32_t sum;
    
    for (sum = 0; number_of_bytes > 0; --number_of_bytes)
            sum += *buffer++;

    sum  = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);

    uint16_t result = ~sum;

    return result;
}

uint16_t Checksum(UDP& header)
{
    /*
    The checksum field is the 16-bit one's complement of the one's complement 
    sum of all 16-bit words in the header. For purposes of computing the 
    checksum, the value of the checksum field is zero.
    */
    ASSERT(header.checksum == 0, "Checksum must be set to zero before calculating the checksum.");

    uint8_t* buffer = (uint8_t*) &header;
    uint8_t  number_of_bytes = sizeof(UDP);

    uint32_t sum;
    
    for (sum = 0; number_of_bytes > 0; --number_of_bytes)
            sum += *buffer++;

    sum  = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);

    uint16_t result = ~sum;

    return result;
}

uint16_t Checksum(TCP& header)
{
    /*
    The checksum field is the 16-bit one's complement of the one's complement 
    sum of all 16-bit words in the header. For purposes of computing the 
    checksum, the value of the checksum field is zero.
    */
    ASSERT(header.checksum == 0, "Checksum must be set to zero before calculating the checksum.");

    uint8_t* buffer = (uint8_t*) &header;
    uint8_t  number_of_bytes = sizeof(TCP);

    uint32_t sum;
    
    for (sum = 0; number_of_bytes > 0; --number_of_bytes)
            sum += *buffer++;

    sum  = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);

    uint16_t result = ~sum;

    return result;
}







// MAKE THESE MORE RUBOST AND WITH ERROR CHECKING!

uint64_t StringToMacAddress(const char* string)
{
    uint32_t number_1 = 0;
    uint32_t number_2 = 0;
    uint32_t number_3 = 0;
    uint32_t number_4 = 0;
    uint32_t number_5 = 0;
    uint32_t number_6 = 0;

    int count = sscanf(
        string,
        "%2x:%2x:%2x:%2x:%2x:%2x", 
        &number_1, &number_2, &number_3, &number_4, &number_5, &number_6
    );

    if (count != 6)
        return 0;

    uint64_t result = (uint64_t(number_1) << 40) | 
                      (uint64_t(number_2) << 32) | 
                      (uint64_t(number_3) << 24) | 
                      (uint64_t(number_4) << 16) | 
                      (uint64_t(number_5) << 8)  | 
                      (uint64_t(number_6) << 0);

    return result;
}
bool MacAddressToString(const MacAddress& address, char* string, size_t size)
{
    snprintf(
        string,
        size,
        "%x:%x:%x:%x:%x:%x", 
        address.data[0], address.data[1], address.data[2], address.data[3], address.data[4], address.data[5]
    );
    return true;
}
bool IPv4AddressToString(uint32_t address, char* buffer, size_t size)
{
    uint8_t number_1 = uint8_t((address & 0xFF000000) >> 24);
    uint8_t number_2 = uint8_t((address & 0x00FF0000) >> 16);
    uint8_t number_3 = uint8_t((address & 0x0000FF00) >> 8);
    uint8_t number_4 = uint8_t((address & 0x000000FF) >> 0);

    snprintf(buffer, size, "%hhu.%hhu.%hhu.%hhu", number_1, number_2, number_3, number_4);
    return true;
}
uint32_t StringToIPv4Address(const char* string)
{
    uint8_t number_1 = 0;
    uint8_t number_2 = 0;
    uint8_t number_3 = 0;
    uint8_t number_4 = 0;

    int count = sscanf(
        string,
        "%hhu.%hhu.%hhu.%hhu", 
        &number_1, &number_2, &number_3, &number_4  
    );

    if (count != 4)
        return 0;

    uint32_t address = (uint32_t(number_1) << 24) | 
                       (uint32_t(number_2) << 16) | 
                       (uint32_t(number_3) << 8)  | 
                       (uint32_t(number_4) << 0);

    return address;
}

uint16_t StringToProtocol(const char* string)
{
    if (strncmp(string, "UDP", 3) == 0 || strncmp(string, "udp", 3) == 0)
        return TRANSPORT_PROTOCOL_UDP;
    if (strncmp(string, "TCP", 3) == 0 || strncmp(string, "TCP", 3) == 0)
        return TRANSPORT_PROTOCOL_TCP;
    return 0;
}
// DANGER! Result has to be used directly. Not thread-safe.
const char* ProtocolToString(uint16_t protocol)
{
    static const size_t BUFFER_SIZE = 8;
    static char buffer[BUFFER_SIZE] = { 0 };
    
    if (protocol == NETWORK_PROTOCOL_IPv4)
        snprintf(buffer, BUFFER_SIZE, "IPv4");
    else if (protocol == NETWORK_PROTOCOL_IPv6)
        snprintf(buffer, BUFFER_SIZE, "IPv6");
    else if (protocol == NETWORK_PROTOCOL_ARP)
        snprintf(buffer, BUFFER_SIZE, "ARP");
    else
        snprintf(buffer, BUFFER_SIZE, "%u", protocol);

    return buffer;
}
const char* ProtocolToString(uint8_t protocol)
{
    static const size_t BUFFER_SIZE = 8;
    static char buffer[BUFFER_SIZE] = { 0 };

    if (protocol == TRANSPORT_PROTOCOL_UDP)
        snprintf(buffer, BUFFER_SIZE, "UDP");
    else if (protocol == TRANSPORT_PROTOCOL_TCP)
        snprintf(buffer, BUFFER_SIZE, "TCP");
    else
        snprintf(buffer, BUFFER_SIZE, "%u", protocol);

    return buffer;
}




uint16_t NetworkByteOrder(uint16_t value)
{
#if LITTLE_ENDIAN_MACHINE  // Conversion needed
    return htons(value);
#elif BIG_ENDIAN_MACHINE  // No conversion needed.
#else
    #error "No endianness specified!"
#endif
}

uint32_t NetworkByteOrder(uint32_t value)
{
#if LITTLE_ENDIAN_MACHINE  // Conversion needed
    return htonl(value);
#elif BIG_ENDIAN_MACHINE  // No conversion needed.
#else
    #error "No endianness specified!"
#endif
}


void FormatToNetwork(Ethernet* ethernet_header)
{
#if LITTLE_ENDIAN_MACHINE  // Conversion needed

    uint8_t* base = (uint8_t *) ethernet_header;

    ethernet_header->protocol = NetworkByteOrder(ethernet_header->protocol);
    if (ethernet_header->protocol == NetworkByteOrder(NETWORK_PROTOCOL_IPv4))
    {
        IPv4* ipv4_header = (IPv4 *) (base + sizeof(Ethernet));

        ipv4_header->total_length        = NetworkByteOrder(ipv4_header->total_length);
        ipv4_header->identification      = NetworkByteOrder(ipv4_header->identification);
        ipv4_header->header_checksum     = NetworkByteOrder(ipv4_header->header_checksum);
        ipv4_header->source_address      = NetworkByteOrder(ipv4_header->source_address);
        ipv4_header->destination_address = NetworkByteOrder(ipv4_header->destination_address);

        if (ipv4_header->protocol == TRANSPORT_PROTOCOL_UDP)
        {
            UDP* udp_header = (UDP *) (base + sizeof(Ethernet) + ipv4_header->header_length * 4);

            udp_header->source_port      = NetworkByteOrder(udp_header->source_port);
            udp_header->destination_port = NetworkByteOrder(udp_header->destination_port);
            udp_header->length           = NetworkByteOrder(udp_header->length);
            udp_header->checksum         = NetworkByteOrder(udp_header->checksum);
        }
        else if (ipv4_header->protocol == TRANSPORT_PROTOCOL_TCP)
        {
            TCP* tcp_header = (TCP *) (base + sizeof(Ethernet) + ipv4_header->header_length * 4);

            tcp_header->source_port      = NetworkByteOrder(tcp_header->source_port);
            tcp_header->destination_port = NetworkByteOrder(tcp_header->destination_port);
            tcp_header->sequence_number  = NetworkByteOrder(tcp_header->sequence_number);
            tcp_header->acknowledgment_number = NetworkByteOrder(tcp_header->acknowledgment_number);
            tcp_header->window_size      = NetworkByteOrder(tcp_header->window_size);
            tcp_header->checksum         = NetworkByteOrder(tcp_header->checksum);
            tcp_header->urgent           = NetworkByteOrder(tcp_header->urgent);

        }
        else
        {
            // ASSERT(false, "Not implemented");
        }
    }
    else
    {
        // ASSERT(false, "Not implemented");
    }


#elif BIG_ENDIAN_MACHINE  // No conversion needed.
#else
    #error "No endianness specified!"
#endif
}






uint8_t HardwareByteOrder(uint8_t value) { return value; }

uint16_t HardwareByteOrder(uint16_t value)
{
#if LITTLE_ENDIAN_MACHINE  // Conversion needed
    return ntohs(value);
#elif BIG_ENDIAN_MACHINE   // No conversion needed.
#else
    #error "No endianness specified!"
#endif
}

uint32_t HardwareByteOrder(uint32_t value)
{
#if LITTLE_ENDIAN_MACHINE  // Conversion needed
    return ntohl(value);
#elif BIG_ENDIAN_MACHINE   // No conversion needed.
#else
    #error "No endianness specified!"
#endif
}

uint64_t HardwareByteOrder(uint64_t value)
{
#if LITTLE_ENDIAN_MACHINE  // Conversion needed
    return ntohll(value);
#elif BIG_ENDIAN_MACHINE   // No conversion needed.
#else
    #error "No endianness specified!"
#endif
}


void FormatToHardware(Ethernet* ethernet_header)
{
#if LITTLE_ENDIAN_MACHINE  // Conversion needed

    ethernet_header->protocol = HardwareByteOrder(ethernet_header->protocol);
    if (ethernet_header->protocol == NETWORK_PROTOCOL_IPv4)
    {
        IPv4* ipv4_header = (IPv4 *) NextHeader(ethernet_header);

        ipv4_header->total_length        = HardwareByteOrder(ipv4_header->total_length);
        ipv4_header->identification      = HardwareByteOrder(ipv4_header->identification);
        ipv4_header->header_checksum     = HardwareByteOrder(ipv4_header->header_checksum);
        ipv4_header->source_address      = HardwareByteOrder(ipv4_header->source_address);
        ipv4_header->destination_address = HardwareByteOrder(ipv4_header->destination_address);

        if (ipv4_header->protocol == TRANSPORT_PROTOCOL_UDP)
        {
            UDP* udp_header = (UDP *) NextHeader(ipv4_header);

            udp_header->source_port      = HardwareByteOrder(udp_header->source_port);
            udp_header->destination_port = HardwareByteOrder(udp_header->destination_port);
            udp_header->length           = HardwareByteOrder(udp_header->length);
            udp_header->checksum         = HardwareByteOrder(udp_header->checksum);
        }
        else if (ipv4_header->protocol == TRANSPORT_PROTOCOL_TCP)
        {
            TCP* tcp_header = (TCP *) NextHeader(ipv4_header);

            tcp_header->source_port      = HardwareByteOrder(tcp_header->source_port);
            tcp_header->destination_port = HardwareByteOrder(tcp_header->destination_port);
            tcp_header->sequence_number  = HardwareByteOrder(tcp_header->sequence_number);
            tcp_header->acknowledgment_number = HardwareByteOrder(tcp_header->acknowledgment_number);
            tcp_header->window_size      = HardwareByteOrder(tcp_header->window_size);
            tcp_header->checksum         = HardwareByteOrder(tcp_header->checksum);
            tcp_header->urgent           = HardwareByteOrder(tcp_header->urgent);

        }
        else
        {
            // printf("UNKNOWN IPv4 payload protocol (%04X)\n\n", ipv4_header->protocol);
        }
    }
    else if (ethernet_header->protocol == NETWORK_PROTOCOL_ARP)
    {
        // printf("Don't handle ARP.\n");
    }
    else 
    {
        // printf("UNKNOWN Ethernet payload protocol (%04X)\n\n", ethernet_header->protocol);
    }


#elif BIG_ENDIAN_MACHINE  // No conversion needed.
#else
    #error "No endianness specified!"
#endif
}
























