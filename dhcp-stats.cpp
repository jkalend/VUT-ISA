#include "dhcp-stats.h"

void print_error(const std::string& error) {
	std::cerr << error << std::endl;
	exit(EXIT_FAILURE);
}

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
		ip_map["warned"] = 0;
		ips.emplace_back(ip_map);
	}
	lines = static_cast<int>(ips.size());
}

DHCPStats::~DHCPStats() {
	if (handle != nullptr) pcap_close(handle);
}

void DHCPStats::update_stats(uint32_t ip) {
	for (auto &subnet : ips) {
		if ((subnet.find("ip")->second & subnet.find("subnet_mask")->second) == (ip & subnet.find("subnet_mask")->second)) {
			subnet.find("used")->second++;
			subnet.find("changed")->second = 1;
			if ((subnet.find("used")->second * 100) / subnet.find("capacity")->second > 50 && subnet.find("warned")->second == 0) {
				syslog(LOG_WARNING,
					   "prefix %s/%d exceeded 50%% of allocations",
					   inet_ntoa((in_addr)subnet.find("ip")->second),
					   subnet.find("prefix")->second
					   );
				move(lines+2, 0);
				refresh();
				std::cout << "prefix " << inet_ntoa((in_addr)subnet.find("ip")->second) << "/" << subnet.find("prefix")->second << " exceeded 50% of allocations" << std::endl;
				lines++;
				subnet.find("warned")->second = 1;
				refresh();
			}
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
		printw("%s/%d %d %d %d%%\n",
			   ipaddr, ip.find("prefix")->second,
			   ip.find("capacity")->second,
			   ip.find("used")->second,
			   (ip.find("used")->second * 100) / ip.find("capacity")->second
			   );
		ip.find("changed")->second = 0;
		line++;
		refresh();
	}
}

uint32_t DHCPStats::parse_packet(const u_char *packet) {
	struct ip *ip_header = (struct ip *) (packet+ETHERNET_HEADER_LEN + VLAN_HEADER_LEN(packet));
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
	while (packet[i] != 0xff) {
		if (packet[i] == 0x35) {
			return_code = (int)packet[i + 2];
			i += (int)packet[++i];
		} else if (packet[i] != 0x00) {
			i += (int)packet[++i];
		}
		i++;
	}
	return return_code;
}

int DHCPStats::sniffer() {
	struct bpf_program fp;
	char filter_exp[] = "port 68 or port 67";
	bpf_u_int32 mask, net;
	struct pcap_pkthdr header;
	const u_char *packet;

	pcap_if_t *alldevsp;
	pcap_findalldevs(&alldevsp, errbuff);
	bool found = false;
	for (auto *d = alldevsp; d != nullptr; d = d->next) {
		if (strcmp(d->name, interface.c_str()) == 0) {
			found = true;
			break;
		}
	}
	if (!found) {
		print_error("Couldn't find device " + interface + ": " + std::string(errbuff));
	}
	if (interface.empty()) {
		print_error("Couldn't find default device: " + std::string(errbuff));
	}
	if (pcap_lookupnet(interface.c_str(), &net, &mask, errbuff) == -1) {
		std::cerr << "Couldn't get netmask for device " << interface << ": " << std::string(errbuff) << std::endl;
		net = 0; mask = 0;
	}
	handle = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1000, errbuff);
	if (handle == nullptr) {
		print_error("Couldn't open device " + interface + ": " + std::string(errbuff));
	}
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		print_error("Couldn't parse filter " + std::string(filter_exp) + ": " + std::string(pcap_geterr(handle)));
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		print_error("Couldn't install filter " + std::string(filter_exp) + ": " + std::string(pcap_geterr(handle)));
	}

	while (true) {
		packet = pcap_next(handle, &header);
		uint32_t result = parse_packet(packet);
		if (result == 0) {
			print_stats();
		} else {
			update_stats(result);
			print_stats();
		}
	}
}


int DHCPStats::read_file() {
    handle = pcap_open_offline(filename.c_str(), errbuff);
	if (handle == NULL) {
		print_error("Couldn't open file " + filename + ": " + std::string(errbuff));
	}

    struct pcap_pkthdr *header;
    const u_char *data;

    while (int returnValue = pcap_next_ex(handle, &header, &data) >= 0) {
		if (parse_packet(data) == 0) {
			print_stats();
			continue;
		}
		update_stats(parse_packet(data));
		print_stats();
    }
	while (true);
}

[[nodiscard]]
bool DHCPStats::filename_is_set() const {
	return filename.empty();
}
