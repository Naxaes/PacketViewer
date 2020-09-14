#include <array>

// Everything will be converted to big endianness just before sending, if needed.
// Bit fields are reorganized by macros.

#define BIG_ENDIAN_MACHINE    0
#define LITTLE_ENDIAN_MACHINE 1


static const uint16_t NETWORK_PROTOCOL_IPv4 = 0x0800;
static const uint16_t NETWORK_PROTOCOL_IPv6 = 0x86DD;
static const uint16_t NETWORK_PROTOCOL_ARP  = 0x0806;

static const uint8_t TRANSPORT_PROTOCOL_UDP = 0x11;
static const uint8_t TRANSPORT_PROTOCOL_TCP = 0x06;



/*
// rfc879: https://tools.ietf.org/html/rfc879#section-1
// The MSS counts only data octets in the segment, it does not count the TCP header or the IP header.
static const uint16_t IPv4_MAXIMUM_SEGMENT_SIZE     = 576;
static const uint16_t TCP_IPV4_MAXIMUM_SEGMENT_SIZE = 576 - IPv4_HEADER_SIZE - TCP_HEADER_SIZE;  // For IPv4.

static const uint16_t ETHERNET_MTU = 1500;
static const uint16_t IPv4_MTU     = ETHERNET_MTU - IPv4_HEADER_SIZE;
static const uint16_t TCP_IPv4_MTU = IPv4_MTU - TCP_HEADER_SIZE;
*/


/*
https://en.wikipedia.org/wiki/Ethernet_frame#Ethernet_II
In order to allow some frames using Ethernet v2 framing and 
some using the original version of 802.3 framing to be used 
on the same Ethernet segment, EtherType values must be greater 
than or equal to 1536 (0x0600). That value was chosen because
the maximum length of the payload field of an Ethernet 802.3 
rame is 1500 octets (0x05DC). Thus if the field's value is 
greater than or equal to 1536, the frame must be an Ethernet 
2 frame, with that field being a type field. If it's less 
than or equal to 1500, it must be an IEEE 802.3 frame, with 
that field being a length field. Values between 1500 and 1536, 
exclusive, are undefined. This convention allows software 
to determine whether a frame is an Ethernet II frame or an IEEE 
802.3 frame, allowing the coexistence of both standards on the 
same physical medium.

Ethernet II can be between 64-1518 bytes.

Since the maximum size of an Ethernet II frame is 1518 bytes, 
subtracting 18 bytes (Datalink overhead) leaves us with 1500 bytes to play with.
*/



/* 
---- TERMINOLOGY -----
Layer 2 packet - Frame
Layer 3 packet - Datagram
Layer 4 packet - Segment

* Maximum Segment  Size (MSS) - Size of payload.
* Maximum Transfer Unit (MTU) - Size of IP-header, TCP-header and payload.

*/


// We could make it more type-safe if we create the following types:
//    * Ethernet_Raw_Packet
//    * Ethernet_IPv4_Raw_Packet
//    * Ethernet_IPv6_Raw_Packet

//    * Ethernet_IPv4_ARP_Packet
//    * Ethernet_IPv6_ARP_Packet

//    * Ethernet_Ipv4_UDP_Raw_Packet
//    * Ethernet_Ipv6_UDP_Raw_Packet
//    * Ethernet_Ipv4_TCP_Raw_Packet
//    * Ethernet_Ipv6_TCP_Raw_Packet

//    * Ethernet_Ipv4_UDP_DNS_Packet
//    * Ethernet_Ipv6_UDP_DNS_Packet

//    * Ethernet_Ipv4_UDP_DHCP_Packet
//    * Ethernet_Ipv6_UDP_DHCP_Packet

//    * Ethernet_Ipv4_UDP_HTTP_Raw_Packet
//    * Ethernet_Ipv6_UDP_HTTP_Raw_Packet
//    * Ethernet_Ipv4_TCP_HTTP_Raw_Packet
//    * Ethernet_Ipv6_TCP_HTTP_Raw_Packet

//    * Ethernet_Ipv4_UDP_HTTPS_Raw_Packet
//    * Ethernet_Ipv6_UDP_HTTPS_Raw_Packet
//    * Ethernet_Ipv4_TCP_HTTPS_Raw_Packet
//    * Ethernet_Ipv6_TCP_HTTPS_Raw_Packet

#pragma push(pack, 1)

// ---- Helper classes ----
struct MacAddress  // TODO(ted): Rename to uint48_t?
{
    uint8_t data[6] = { 0 };

    // Constructors
    MacAddress()                        noexcept {                              }
    MacAddress(uint64_t value)          noexcept { memcpy(data, &value, 6);     }
    MacAddress(const MacAddress& other) noexcept { memcpy(data, other.data, 6); }

    MacAddress(uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint8_t e, uint8_t f) noexcept 
    {
        data[0] = a;
        data[1] = b;
        data[2] = c;
        data[3] = d;
        data[4] = e;
        data[5] = f;
    }

    // Assignment operators
    MacAddress& operator= (uint64_t value)          noexcept { memcpy(data, &value, 6);     return *this; }
    MacAddress& operator= (const MacAddress& other) noexcept { memcpy(data, other.data, 6); return *this; }

    // Comparison operators
    bool operator== (uint64_t value) const noexcept { return memcmp(data, &value, 6) == 0; }
    bool operator!= (uint64_t value) const noexcept { return memcmp(data, &value, 6) != 0; }

    // Implicit conversion.
    operator uint64_t () const noexcept { uint64_t value = 0; return *(uint64_t *) memcpy(&value, data, 6); }

} __attribute__((packed));



// ---- Protocol Headers ----
struct Ethernet
{
    static const uint16_t ADDRESS_SIZE     = ETHER_ADDR_LEN;  // 6 bytes
    static const uint16_t ETHER_TYPE_SIZE  = ETHER_TYPE_LEN;  // 2 bytes
    static const uint16_t CRC_SIZE         = ETHER_CRC_LEN;   // 4 bytes

    static const uint16_t HEADER_SIZE      = ETHER_HDR_LEN;
    static const uint16_t MAX_TOTAL_SIZE   = ETHER_MAX_LEN;  // 1518
    static const uint16_t MAX_PAYLOAD_SIZE = MAX_TOTAL_SIZE - HEADER_SIZE;

    std::array<uint8_t, 14> AsByteArray() const noexcept
    {
        return {
                destination_mac_address.data[0],
                destination_mac_address.data[1],
                destination_mac_address.data[2],
                destination_mac_address.data[3],
                destination_mac_address.data[4],
                destination_mac_address.data[5],
                source_mac_address.data[0],
                source_mac_address.data[1],
                source_mac_address.data[2],
                source_mac_address.data[3],
                source_mac_address.data[4],
                source_mac_address.data[5],
                uint8_t(protocol >> 8u),
                uint8_t(protocol >> 0u),
        };
    }

    static_assert(sizeof(MacAddress) == Ethernet::ADDRESS_SIZE, "MacAddress is wrong size.");
    MacAddress destination_mac_address;
    MacAddress source_mac_address;

    // Values of 1500 and below mean that it is used to indicate the size of the payload in octets, while values 
    // of 1536 and above indicate that it is used as an EtherType, to indicate which protocol is encapsulated in 
    // the payload of the frame. 
    uint16_t protocol; // ether_type;

} __attribute__((packed));


// Address Resolution Protocol (Neighbor Discovery Protocol in IPv6).
struct ARP
{
    uint8_t  hardware_type;
    uint8_t  protocol_type;
    uint16_t hardware_length;
    uint16_t protocol_length;
    uint8_t  operation;
    MacAddress sender_mac_address;
    uint32_t sender_ip_address;
    MacAddress target_mac_address;
    uint32_t target_ip_address;

    std::array<uint8_t, 27> AsByteArray() const noexcept
    {
        return {
                uint8_t(hardware_type),
                uint8_t(protocol_type),
                uint8_t(hardware_length >> 8u),
                uint8_t(hardware_length >> 0u),
                uint8_t(protocol_length >> 8u),
                uint8_t(protocol_length >> 0u),
                uint8_t(operation),
                sender_mac_address.data[0],
                sender_mac_address.data[1],
                sender_mac_address.data[2],
                sender_mac_address.data[3],
                sender_mac_address.data[4],
                sender_mac_address.data[5],
                uint8_t(sender_ip_address >> 24u),
                uint8_t(sender_ip_address >> 16u),
                uint8_t(sender_ip_address >> 8u),
                uint8_t(sender_ip_address >> 0u),
                target_mac_address.data[0],
                target_mac_address.data[1],
                target_mac_address.data[2],
                target_mac_address.data[3],
                target_mac_address.data[4],
                target_mac_address.data[5],
                uint8_t(target_ip_address >> 24u),
                uint8_t(target_ip_address >> 16u),
                uint8_t(target_ip_address >> 8u),
                uint8_t(target_ip_address >> 0u),
        };
    }
} __attribute__((packed));


// TODO(ted): Fix endianness!
struct IPv6
{
    struct Address {
        uint8_t data[16];
    } __attribute__((packed));

    uint8_t  version:4,
             traffic_class_1:4;
    uint8_t  traffic_class_2:4,
             flow_label_1:4;
    uint16_t flow_label_2;
    uint16_t payload_length;
    uint8_t  next_header;           // Pointer to the next extension header or the payload header.
    uint8_t  hop_limit;
    Address  source_address;
    Address  destination_address;

    std::array<uint8_t, 32> AsByteArray()
    {
        // TODO(ted): Fix endianness!
        return {
                uint8_t(version << 0u | traffic_class_1 >> 4u),
                uint8_t(traffic_class_2 << 0u | flow_label_1 >> 4u),
                uint8_t(flow_label_2 >> 8u),
                uint8_t(flow_label_2 >> 0u),
                uint8_t(payload_length >> 8u),
                uint8_t(payload_length >> 0u),
                uint8_t(next_header),
                uint8_t(hop_limit),
                source_address.data[0],
                source_address.data[1],
                source_address.data[2],
                source_address.data[3],
                source_address.data[4],
                source_address.data[5],
                destination_address.data[0],
                destination_address.data[1],
                destination_address.data[2],
                destination_address.data[3],
                destination_address.data[4],
                destination_address.data[5],
        };
    }

} __attribute__((packed));


// https://tools.ietf.org/html/rfc791
struct IPv4 
{
    static const uint16_t HEADER_SIZE      = 20;     // Bytes
    static const uint16_t MAX_TOTAL_SIZE   = 65535;  // Practical size is roughly 8Kb.
    static const uint16_t MAX_PAYLOAD_SIZE = MAX_TOTAL_SIZE - HEADER_SIZE;
    static const uint16_t MIN_OPTION_SIZE  = 20;
    static const uint16_t MAX_OPTION_SIZE  = 60;

    // Payload protocols
    static const uint8_t PROTOCOL_ICMP = 0x01;  // 1
    static const uint8_t PROTOCOL_IP   = 0x04;  // 4
    static const uint8_t PROTOCOL_TCP  = 0x06;  // 6
    static const uint8_t PROTOCOL_UDP  = 0x11;  // 17
    static const uint8_t PROTOCOL_IPv6 = 0x29;  // 41
    static const uint8_t PROTOCOL_RSVP = 0x2E;  // 46

    std::array<uint8_t, IPv4::HEADER_SIZE> AsByteArray() const noexcept
    {
        return {
            uint8_t((version << 4u) | (header_length << 0u)),
            uint8_t((precedence << 5u) | (delay << 4u) | (throughput << 3u) | (reliability << 2u) | (reserved1 << 0u)),
            uint8_t(total_length >> 8),
            uint8_t(total_length),
            uint8_t(identification >> 8u),
            uint8_t(identification),
            uint8_t(fragment_offset),
            uint8_t((reserved1 << 7u) | (DF << 6u) | (MF << 5u) | (uint8_t(fragment_offset >> 8u))),
            time_to_live,
            protocol,
            uint8_t(header_checksum >> 8u),
            uint8_t(header_checksum >> 0u),
            uint8_t(source_address >> 24u),
            uint8_t(source_address >> 16u),
            uint8_t(source_address >> 8u),
            uint8_t(source_address >> 0u),
            uint8_t(destination_address >> 24u),
            uint8_t(destination_address >> 16u),
            uint8_t(destination_address >> 8u),
            uint8_t(destination_address >> 0u),
        };
    }


#if BIG_ENDIAN_MACHINE
    uint8_t  version:4,             // The version of the IP protocol. For IPv4, this field has a value of 4.
             header_length:4;       // The length of the header in 32-bit words. The minumum value is 20 bytes, and the maximum value is 60 bytes.

    uint8_t  precedence:3,          // Specifies how the datagram should be handled.
             delay:1,
             throughput:1,
             reliability:1,
             reserved1:2;

    uint16_t total_length;          // The length of the entire packet (header + data). The minimum length is 20 bytes, and the maximum is 65,535 bytes.

    uint16_t identification;        // Used to differentiate fragmented packets from different datagrams.

    // TODO(ted): MAKE SURE THIS ISN'T WRONG!! I think we need to change it to accomidate the endianness.
    uint16_t reserved2:1,           // Used to control or identify fragments.
             DF:1,
             MF:1,              
             fragment_offset:13;    // Used for fragmentation and reassembly if the packet is too large to put in a frame.

#elif LITTLE_ENDIAN_MACHINE
    uint8_t  header_length:4,       // The length of the header in 32-bit words. The minimum value is 20 bytes, and the maximum value is 60 bytes.
             version:4;             // The version of the IP protocol. For IPv4, this field has a value of 4.

    // TODO(ted): This is not the current representation. Use DSCP (6 bytes) and ECN (2 bytes) instead.
    uint8_t  reserved1:1,
             cost:1,                // 0 = Normal cost,        1 = Minimize cost
             reliability:1,         // 0 = Normal reliability, 1 = High reliability
             throughput:1,          // 0 = Normal throughput,  1 = High throughput
             delay:1,               // 0 = Normal delay,       1 = Low delay
             precedence:3;          // Relative priority when packets needs to be dropped.
    
    uint16_t total_length;          // The length of the entire packet (header + data). The minimum length is 20 bytes, and the maximum is 65,535 bytes.

    uint16_t identification;        // Used to differentiate fragmented packets from different datagrams.

    uint16_t fragment_offset:13,    // Relative position of a fragment with respect to the whole fragment (in 8 bytes).
             MF:1,                  // More fragments. Set to 1 for all fragments except the last.
             DF:1,                  // Don't fragment. Set to 1 if the datagram shouldn't be fragmented.
             reserved2:1;           // Reserved for future use (should be 0).
#else
    #error "No endianness specified!"
#endif

    uint8_t  time_to_live;          // Limits a datagram’s lifetime. If the packet doesn’t get to its destination before the TTL expires, it is discarded.

    uint8_t  protocol;              // Defines the protocol used in the data portion of the IP datagram. For example, TCP is represented by the number 6 and UDP by 17.

    uint16_t header_checksum;       // Used for error-checking of the header. If a packet arrives at a router and the router calculates a different checksum than the one specified in this field, the packet will be discarded.

    uint32_t source_address;        // The IP address of the host that sent the packet.

    uint32_t destination_address;   // The IP address of the host that should receive the packet.

} __attribute__((packed));


struct IPv4OptionSourceRoute
{
    // code
    uint8_t copy:2,
            class_:2,
            option_number:4;
    uint8_t length;

};


struct ICMP
{
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
};

 
struct UDP
{
    // TODO(ted): Dependent on the underlying protocol.
    static const uint16_t HEADER_SIZE      = 8;
    static const uint16_t MAX_TOTAL_SIZE   = 65535;
    static const uint16_t MAX_PAYLOAD_SIZE = MAX_TOTAL_SIZE - HEADER_SIZE - IPv4::HEADER_SIZE;

    std::array<uint8_t, 8> ReadAsByteArray() const noexcept
    {
        return {
            uint8_t(source_port >> 8u),
            uint8_t(source_port >> 0u),
            uint8_t(destination_port >> 8u),
            uint8_t(destination_port >> 0u),
            uint8_t(length >> 8u),
            uint8_t(length >> 0u),
            uint8_t(checksum >> 8u),
            uint8_t(checksum >> 0u),
        };
    }

    uint16_t source_port;       // Port number of the application on the host sending the data.

    uint16_t destination_port;  // Port number of the application on the host receiving the data.

    uint16_t length;            // The length of the UDP header and data.

    uint16_t checksum;          // The checksum of both the UDP header and UDP data fields.

} __attribute__((packed));


struct TCP
{
    // TODO(ted): Dependent on the underlying protocol.
    static const uint16_t HEADER_SIZE       = 20;
    static const uint16_t MAX_TOTAL_SIZE    = 1500;
    static const uint16_t MAX_PAYLOAD_SIZE  = MAX_TOTAL_SIZE - HEADER_SIZE - IPv4::HEADER_SIZE;


    std::array<uint8_t, 20> ReadAsByteArray() const noexcept
    {
        return {
            uint8_t(source_port >> 8u),
            uint8_t(source_port >> 0u),
            uint8_t(destination_port >> 8u),
            uint8_t(destination_port >> 0u),
            uint8_t(sequence_number >> 24u),
            uint8_t(sequence_number >> 16u),
            uint8_t(sequence_number >> 8u),
            uint8_t(sequence_number >> 0u),
            uint8_t(acknowledgment_number >> 24u),
            uint8_t(acknowledgment_number >> 16u),
            uint8_t(acknowledgment_number >> 8u),
            uint8_t(acknowledgment_number >> 0u),
            uint8_t(data_offset << 4u | (reserved << 1u) | (flag_ns << 0u)),
            uint8_t(flag_cwr << 7u | (flag_ece << 6u) | (flag_urg << 5u) | (flag_ack << 4u) | (flag_psh << 3u) | (flag_rst << 2u) | (flag_syn << 1u) | (flag_fin << 0u)),
            uint8_t(window_size >> 8u),
            uint8_t(window_size >> 0u),
            uint8_t(checksum >> 8u),
            uint8_t(checksum >> 0u),
            uint8_t(urgent >> 8u),
            uint8_t(urgent >> 0u),
        };
    }


    uint16_t source_port;       // Port number of the application on the host sending the data.

    uint16_t destination_port;  // Port number of the application on the host receiving the data.

    uint32_t sequence_number;   // Used to identify each byte of data.

    uint32_t acknowledgment_number; // The next sequence number that the receiver is expecting.

#if BIG_ENDIAN_MACHINE
    uint8_t  data_offset : 4,   // The size of the TCP header in 32-bit words. Set to 5 if no options are present.
             reserved    : 3,   // Always set to 0.  
             flag_ns     : 1,
    uint8_t  flag_cwr    : 1,   // Congestion Window Reduced.
             flag_ece    : 1,   
             flag_urg    : 1,
             flag_ack    : 1,
             flag_psh    : 1,   // Push function.
             flag_rst    : 1,   // Reset the connection.
             flag_syn    : 1,   // Synchronize sequence numbers.
             flag_fin    : 1;   // Last packet from sender.

#elif LITTLE_ENDIAN_MACHINE
    uint8_t  flag_ns     : 1u,
             reserved    : 3u,   // Always set to 0.
             data_offset : 4u;   // The size of the TCP header in 32-bit words.
    uint8_t  flag_fin    : 1u,   // Last packet from sender.
             flag_syn    : 1u,   // Synchronize sequence numbers.
             flag_rst    : 1u,   // Reset the connection.
             flag_psh    : 1u,   // Push function.
             flag_ack    : 1u,
             flag_urg    : 1u,
             flag_ece    : 1u,
             flag_cwr    : 1u;   // Congestion Window Reduced.
#else
    #error "No endianness specified!"
#endif

    uint16_t window_size;       // The window size the sender is willing to accept (between 2 and 65535 bytes).

    uint16_t checksum;          // Used for error-checking of the header and data.

    uint16_t urgent;            // Indicates the offset from the current sequence number, where the segment of non-urgent data begins.

} __attribute__((packed));


#pragma pop(pack)















