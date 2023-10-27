#ifndef VUT_ISA_DHCP_STATS_H
#define VUT_ISA_DHCP_STATS_H

#include "argparse.h"
#include <ncurses.h>
#include <pcap/pcap.h>
#include <map>
#include <cmath>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ether.h>

#define ETHERNET_HEADER_LEN 14
#define VLAN_HEADER_LEN(ether) (ntohs( ((struct ether_header *)ether)->ether_type ) == ETHERTYPE_VLAN ? 4 : 0)
#define IP_HEADER_LEN(data) (((data[ETHERNET_HEADER_LEN + VLAN_HEADER_LEN(data)] & 0x0F) * 4) + VLAN_HEADER_LEN(data))
#define UDP_HEADER_LEN 8
#define DHCP_HEADER_LEN 236
#define DHCP_MAGIC_COOKIE 0x63825363
#define DHCP_OPTION_OFFSET(data) (data + ETHERNET_HEADER_LEN+IP_HEADER_LEN(data)+UDP_HEADER_LEN+DHCP_HEADER_LEN+sizeof(DHCP_MAGIC_COOKIE))


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
//	u_char *options;
};


class DHCPStats {
private:
	int lines = 1;
	std::vector<std::map<std::string, int>> ips;
	std::string interface;
	std::string filename;
	pcap_t *handle = nullptr;
	char errbuff[PCAP_ERRBUF_SIZE] = {0};

	/// Parse DHCP options
	/// \param packet The packet
	/// \return The DHCP Message Type
	int parse_options(const u_char *packet);

	/// Print or refresh the stats on the screen
	void print_stats();

	/// Update the stats
	/// \param ip The IP address
	void update_stats(uint32_t ip);

	/// Parse the packet
	/// \param packet The packet
	/// \return The IP address
	uint32_t parse_packet(const u_char *packet);

public:
	/// Constructor
	/// \param argc The number of arguments
	/// \param argv The arguments
	explicit
	DHCPStats(int argc, char **argv);

	~DHCPStats();

	/// Calculate subnet capacity
	/// \param subnet The subnet
	/// \return The capacity
	static int calculate_subnet_capacity(const std::string& subnet);

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

#endif //VUT_ISA_DHCP_STATS_H
