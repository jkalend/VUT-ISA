# dhcp-stats

## Author
 - Jan Kalenda (xkalen07)
 - 17.11.2023

## Description
The dhcp-stats is a monitor that monitors a DHCP server and observer specified subnets and their usage rate.
When 50% is reached a system log is created warning the user about the situation.

## Usage
```
./dhcp-stats [-h] [-i INTERFACE] [-r FILE] [ SUBNETS [SUBNETS ...]]
```
where:
 - -h show this help message and exit
 - -i INTERFACE interface to listen on
 - -r FILE file to read from
 - SUBNETS subnets to observe, format: IP/MASK

Only one of -i and -r can be used.

## Example
```
./dhcp-stats -i lo 192.168.0.0/22 192.168.1.0/24 172.16.32.0/24 192.168.1.0/26 192.168.1.0/27
IP-Prefix       Max-hosts       Allocated addresses     Utilization
192.168.0.0/22  1022            50                      4.89%
192.168.1.0/24  254             50                      19.69%
172.16.32.0/24  254             0                       0.00%
192.168.1.0/26  62              50                      80.65%
192.168.1.0/27  30              30                      100.00%

prefix 192.168.1.0/27 exceeded 50% of allocations
prefix 192.168.1.0/26 exceeded 50% of allocations
```

## Extensions
 - -h argument is added
 - support for Option Overload
 - support for single layer of VLAN
 - support for counting of allocated addresses of DNS servers, DHCP server, routers and other (options 3-11, and option 54)

## Limitations
 - only one of -i and -r can be used
 - only one layer of VLAN is supported
 - supports only IPv4
 - does not support tunneling
 - does not support lease time

## File list
 - README.md - this file
 - Makefile - makefile for building the project
 - main.cpp - main file of the project
 - dhcp-stats.cpp - source code of the project
 - dhcp-stats.h - header file of the project
 - subnet.cpp - source code of the subnet class
 - subnet.h - header file of the subnet class
 - argparse.cpp - source code of the argument parser
 - argparse.h - header file of the argument parser
 - dhcp-stats.1 - man page of the project
 - manual.pdf - documentation of the project
