#include "subnet.h"

Subnet::Subnet(const std::string &ip) {
	const std::string netip = ip.substr(0, ip.find('/'));
	const uint32_t subnet_mask = std::stoi(ip.substr(ip.find('/') + 1));
	this->ip = inet_addr(netip.c_str());
	this->capacity = calculate_subnet_capacity(ip);
	this->subnet_mask = ntohl(~0 << (32 - subnet_mask));
	this->prefix = subnet_mask;
	this->first_ip = this->ip & this->subnet_mask;
	this->last_ip = this->ip | ~this->subnet_mask;
}

uint32_t Subnet::calculate_subnet_capacity(const std::string& subnet) {
	uint32_t capacity = 0;
	const std::string subnet_mask = subnet.substr(subnet.find('/') + 1);
	if (const uint8_t mask = std::stoi(subnet_mask); mask == 32) {
		capacity = 1;
	}
	else {
		capacity = static_cast<uint32_t>(pow(2, 32 - mask) - 2);
	}
	return capacity;
}

float Subnet::calculate_subnet_fullness() const {
	return static_cast<float>(address_map.size()) * 100 / static_cast<float>(capacity);
}

int Subnet::get_subnet_used_count() const {
	return static_cast<int>(address_map.size());
}
