#include "dhcp-stats.h"
#include <netinet/ip.h>

int DHCPStats::calculate_subnet_capacity(const std::string& subnet) {
	int capacity = 0;
	std::string subnet_mask = subnet.substr(subnet.find('/') + 1);
	if (int mask = std::stoi(subnet_mask); mask == 32) {
		capacity = 1;
	}
	else {
		capacity = static_cast<int>(pow(2, 32 - mask));
	}
	return capacity - 2;
}

DHCPStats::DHCPStats(int argc, char **argv) {
	ArgParse argparse(argc, argv);
	interface = argparse.get_interface();
	filename = argparse.get_filename();
	for (auto const &ip : argparse.get_ips()) {
		std::string netip = ip.substr(0, ip.find('/'));
		uint32_t subnet_mask = std::stoi(ip.substr(ip.find('/') + 1));
		std::map<std::string, int> ip_map;
		ip_map["ip"] = inet_addr(netip.c_str());
		ip_map["capacity"] = calculate_subnet_capacity(ip);
		ip_map["subnet_mask"] = ntohl(~0 << (32 - subnet_mask));
		ip_map["prefix"] = subnet_mask;
		ip_map["used"] = 0;
		ip_map["changed"] = 1;
		ips.emplace_back(ip_map);
	}
}

void DHCPStats::update_stats(uint32_t ip) {
	for (auto &subnet : ips) {
		if ((subnet.find("ip")->second & subnet.find("subnet_mask")->second) == (ip & subnet.find("subnet_mask")->second)) {
			subnet.find("used")->second++;
			subnet.find("changed")->second = 1;
		}
	}
}

void DHCPStats::print_stats() {
	int line = 1;
	for (auto &ip : ips) {
		if (ip.find("changed")->second == 0) {
			line++;
			continue;
		}
		move(line, 0);
		clrtoeol();
		char *ipaddr = inet_ntoa(*(in_addr*)&ip.find("ip")->second);
		printw("%s/%d %d %d %d%%\n", ipaddr, ip.find("prefix")->second, ip.find("capacity")->second, ip.find("used")->second, (ip.find("used")->second * 100) / ip.find("capacity")->second);
		ip.find("changed")->second = 0;
		line++;
	}
	refresh();
}

uint32_t DHCPStats::parse_packet(const u_char *packet) {
	struct ip *ip_header = (struct ip *) (packet+ETHERNET_HEADER_LEN);
	if (ntohs(ip_header->ip_len) < DHCP_HEADER_LEN) {
		return 0;
	}
	struct DHCPHeader *dhcp_header = (struct DHCPHeader *) (packet+ETHERNET_HEADER_LEN+IP_HEADER_LEN(packet)+UDP_HEADER_LEN);

	if (dhcp_header->op != 2) {
		return 0;
	}
	auto *payload = DHCP_OPTION_OFFSET(packet);

	if(parse_options(payload) == 5) {
//		dhcp_header->yiaddr = inet_addr("192.168.1.12");
		return dhcp_header->yiaddr;
	}
	return 0;
}

int DHCPStats::parse_options(const u_char *packet) {
	int return_code = 0;
	int i = 0;
	while ((packet[i] & 0xff) != 0xff) {
//		if (packet[i] == 1) {
//			*mask = (0xffffffff & *((uint32_t*) (packet + i + 2)));
//			i += (int)packet[++i];
//		}
		if (((packet[i] & 0x35) == 0x35)) {
			return_code = (int)packet[i + 2];
			i += (int)packet[++i];
		} else {
			i += (int)packet[++i];
		}
		i++;
	}
	return return_code;
}

int DHCPStats::sniffer(const std::string dev) {
	pcap_t *handle;			/* Session handle */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct bpf_program fp;		/* The compiled filter */
	char filter_exp[] = "port 80 or port 67";	/* The filter expression */
	bpf_u_int32 mask;		/* Our netmask */
	bpf_u_int32 net;		/* Our IP */
	struct pcap_pkthdr header;	/* The header that pcap gives us */
	const u_char *packet;		/* The actual packet */

	/* Define the device */
	pcap_if_t *alldevsp;
	pcap_findalldevs(&alldevsp, errbuf);
	bool found = false;
	for (auto *d = alldevsp; d != NULL; d = d->next) {
		if (strcmp(d->name, dev.c_str()) == 0) {
			found = true;
			break;
		}
	}
	if (!found) {
		fprintf(stderr, "Couldn't find device %s: %s\n", dev.c_str(), errbuf);
		return 2;
	}
	if (dev == "") {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return 2;
	}
	/* Find the properties for the device */
	if (pcap_lookupnet(dev.c_str(), &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev.c_str(), errbuf);
		net = 0;
		mask = 0;
	}
	/* Open the session in promiscuous mode */
	handle = pcap_open_live(dev.c_str(), BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev.c_str(), errbuf);
		return 2;
	}
	/* Compile and apply the filter */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return 2;
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return 2;
	}
	while (true) {
		/* Grab a packet */
		packet = pcap_next(handle, &header);
		/* Print its length */
		uint32_t result = parse_packet(packet);
		if (result == 0) {
			print_stats();
		} else {
			update_stats(result);
			print_stats();
		}
	}
	return 0;
}
