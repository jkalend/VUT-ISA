#include "dhcp-stats.h"

int test(DHCPStats &dhcp_stats) {
	char errbuff[PCAP_ERRBUF_SIZE];

    /*
    * Step 4 - Open the file and store result in pointer to pcap_t
    */

    // Use pcap_open_offline
    // http://www.winpcap.org/docs/docs_41b5/html/group__wpcapfunc.html#g91078168a13de8848df2b7b83d1f5b69
    pcap_t * pcap = pcap_open_offline(dhcp_stats.filename.c_str(), errbuff);

    /*
    * Step 5 - Create a header and a data object
    */

    // Create a header object:
    // http://www.winpcap.org/docs/docs_40_2/html/structpcap__pkthdr.html
    struct pcap_pkthdr *header;

    // Create a character array using a u_char
    // u_char is defined here:
    // C:\Program Files (x86)\Microsoft SDKs\Windows\v7.0A\Include\WinSock2.h
    // typedef unsigned char   u_char;
    const u_char *data;

    /*
    * Step 6 - Loop through packets and print them to screen
    */
    while (int returnValue = pcap_next_ex(pcap, &header, &data) >= 0) {
		if (dhcp_stats.parse_packet(data) == 0) {
			dhcp_stats.print_stats();
			continue;
		}
		dhcp_stats.update_stats(dhcp_stats.parse_packet(data));
		dhcp_stats.print_stats();
    }
	return 0;
}

int main(int argc , char **argv) {
	initscr();
	openlog("dhcp-stats", LOG_PID | LOG_NDELAY, LOG_DAEMON);

	DHCPStats dhcp_stats(argc, argv);
	printw("IP-Prefix Max-hosts Allocated addresses Utilization\n");
	if (!dhcp_stats.filename.empty()) {
		test(dhcp_stats);
		getch();
	} else {
		dhcp_stats.sniffer(dhcp_stats.interface);
	}
	endwin();
//	dhcp_stats.sniffer(dhcp_stats.interface);
//	dhcp_stats.print_stats();

	closelog();
}
