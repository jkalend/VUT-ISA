#ifndef VUT_ISA_DHCP_STATS_H
#define VUT_ISA_DHCP_STATS_H

#include "argparse.h"
#include "subnet.h"
#include <ncurses.h>
#include <unistd.h>
#include <pcap/pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <memory>

/// \brief Length of the ethernet header
#define ETHERNET_HEADER_LEN 14

/// \brief Length of the VLAN header
#define VLAN_HEADER_LEN(ether) (ntohs( ((struct ether_header *)ether)->ether_type ) == ETHERTYPE_VLAN ? 4 : 0)

/// \brief Length of the IP header
#define IP_HEADER_LEN(data) (((data[ETHERNET_HEADER_LEN + VLAN_HEADER_LEN(data)] & 0x0F) * 4) + VLAN_HEADER_LEN(data))

/// \brief Length of the UDP header
#define UDP_HEADER_LEN 8

/// \brief Length of the DHCP header (without options)
#define DHCP_HEADER_LEN 236

/// \brief DHCP magic cookie
#define DHCP_MAGIC_COOKIE 0x63825363

/// \brief Offset of the DHCP options
#define DHCP_OPTION_OFFSET(data) (data + ETHERNET_HEADER_LEN+IP_HEADER_LEN(data)+UDP_HEADER_LEN+DHCP_HEADER_LEN+sizeof(DHCP_MAGIC_COOKIE))

/// \brief DHCP header structure (without options)
struct DHCPHeader {
	uint8_t op;
	uint8_t htype;
	uint8_t hlen;
	uint8_t hops;
	uint32_t xid;
	uint16_t secs;
	uint16_t flags;
	uint32_t ciaddr;
	uint32_t yiaddr;
	uint32_t siaddr;
	uint32_t giaddr;
	uint8_t chaddr[16];
	uint8_t sname[64];
	uint8_t file[128];
	uint32_t magic_cookie;
	//	options here
};

class DHCPStats {
private:
	/// \brief used to print the stats on the screen
	int lines = 1;

	/// \brief vector of subnets
	std::vector<Subnet> ips;
	std::string interface;
	std::string filename;

	/// \brief pcap handle
	pcap_t *handle = nullptr;
	char errbuff[PCAP_ERRBUF_SIZE] = {0};

	/// Parse DHCP options
	/// \param packet The packet
	/// \return The DHCP Message Type
	int parse_options(const u_char *packet, int *overload, int length);

	/// Print or refresh the stats on the screen
	void print_stats();

	/// Update the stats
	/// \param ip The IP address
	void update_stats(uint32_t ip);

	/// Parse the packet
	/// \param packet The packet
	/// \return The IP address or 0 if the packet does not contain DHCP message
	uint32_t parse_packet(const u_char *packet);

public:
	/// Constructor
	/// \param argc The number of arguments
	/// \param argv The arguments
	explicit
	DHCPStats(int argc, char **argv);

	~DHCPStats();

	/// Check if the filename is set
	/// \return True if the filename is set, false otherwise
	[[nodiscard]]
	bool filename_is_set() const;

	/// Sniff the packets
	/// \return 1 on failure
	int sniffer();

	/// Read the file
	/// \return 1 on failure
	int read_file();
};

/// \brief global pointer to DHCPStats
extern std::unique_ptr<DHCPStats> dhcp_stats;

#endif //VUT_ISA_DHCP_STATS_H
