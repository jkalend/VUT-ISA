//
// Created by Petr on 20.10.2023.
//

#ifndef VUT_ISA_UDPHEADER_H
#define VUT_ISA_UDPHEADER_H

#include <cstdint>
#include <cstdlib>
#include <netinet/in.h>
#include <arpa/inet.h>

class UDPHeader {

public:
	uint16_t source_port;
	uint16_t destination_port;
	uint16_t length;
	uint16_t checksum;
	UDPHeader(const u_char *data);
	~UDPHeader() = default;
};

#endif //VUT_ISA_UDPHEADER_H
