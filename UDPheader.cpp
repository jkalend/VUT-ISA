#include "UDPheader.h"


UDPHeader::UDPHeader(const u_char *data) {
	source_port = ntohs(*(uint16_t*)data);
	destination_port = ntohs(*(uint16_t*)(data + 2));
	length = ntohs(*(uint16_t*)(data + 4));
	checksum = ntohs(*(uint16_t*)(data + 6));
}
