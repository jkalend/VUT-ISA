#include "dhcp-stats.h"
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

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
    u_int packetCount = 0;
    while (int returnValue = pcap_next_ex(pcap, &header, &data) >= 0)
    {
        // Print using printf. See printf reference:
        // http://www.cplusplus.com/reference/clibrary/cstdio/printf/

        // Show the packet number
        printf("Packet # %i\n", ++packetCount);

        // Show the size in bytes of the packet
        printf("Packet size: %d bytes\n", header->len);

        // Show a warning if the length captured is different
        if (header->len != header->caplen)
            printf("Warning! Capture size different than packet size: %ld bytes\n", header->len);

        // Show Epoch Time
        printf("Epoch Time: %d:%d seconds\n", header->ts.tv_sec, header->ts.tv_usec);

        // loop through the packet and print it as hexidecimal representations of octets
        // We also have a function that does this similarly below: PrintData()

		// Ethernet header is 14 bytes
		// IP header length is at data[14] in words
		// UDP header is 8 bytes
		// 16 is yiaddr offset
		// 236 options offset
		// 4 is magic cookie offset
//		std::cout << "offset: " << DHCP_OPTION_OFFSET(data)<< std::endl;
//		struct DHCPHeader *dhcp_header = (struct DHCPHeader *) (data+ETHERNET_HEADER_LEN+IP_HEADER_LEN(data)+UDP_HEADER_LEN);
//		u_char *payload = (u_char *) (DHCP_OPTION_OFFSET(data));
//		char a[2] = {0x1, 0x34};
//		uint16_t b = *(uint16_t *)a;
//		b = ntohs(b);
//		std::cout << "option: " << b << std::endl;

//		std::cout << dhcp_stats.parse_packet(data) << std::endl;


//	    memcpy(&a, data+14+(data[14] & 15)*4+8+236, sizeof(a)); // destination IP
//		std::cout << a << std::endl;


		std::cout << "IP: " << dhcp_stats.parse_packet(data) << std::endl;

//        for (u_int i=0; (i < header->caplen ) ; i++)
//        {
//            // Start printing on the next after every 16 octets
//            if ( (i % 16) == 0) printf("\n");
//
//            // Print each octet as hex (x), make sure there is always two characters (.2).
//            printf("%.2x ", data[i]);
//        }
//
        // Add two lines between packets
        printf("\n\n");
    }
	return 0;
}

int main(int argc , char **argv) {
//	initscr();
	openlog("dhcp-stats", LOG_PID | LOG_NDELAY, LOG_DAEMON);

	DHCPStats dhcp_stats(argc, argv);
//	ArgParse argparse(argc, argv);
	test(dhcp_stats);
//	dhcp_stats.sniffer();
//	dhcp_stats.print_stats();

	closelog();
}
