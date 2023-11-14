#ifndef VUT_ISA_SUBNET_H
#define VUT_ISA_SUBNET_H
#include <map>
#include <string>
#include <cmath>
#include <netinet/in.h>
#include <arpa/inet.h>

class Subnet {
public:
	Subnet(const std::string &ip);
	~Subnet() = default;

	in_addr_t ip;
	uint32_t capacity;
	uint32_t subnet_mask;
	uint32_t prefix;
	bool changed = true;
	bool warned = false;
	uint32_t first_ip;
	uint32_t last_ip;

	/// \brief map of used addresses
	std::map<uint32_t, bool> address_map;

	/// \brief Calculate subnet curren capacity in percentage
	/// \return The fullness of the subnet in percentage
	[[nodiscard]] float calculate_subnet_fullness() const;

	/// \brief Calculate subnet used count
	/// \return subnet used count
	[[nodiscard]] int get_subnet_used_count() const;
private:
	/// Calculate maximum subnet capacity
	/// \param subnet The subnet
	/// \return The capacity
	static uint32_t calculate_subnet_capacity(const std::string& subnet);

};

#endif //VUT_ISA_SUBNET_H
