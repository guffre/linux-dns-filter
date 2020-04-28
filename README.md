# linux-dns-filter
Linux kernel module that drops all DNS requests. You could make this the basis for a simple firewall, since it does the parsing of TCP/UDP packets down to the packet data.

# Installation
    make
    insmod dns_filter.ko
    
# Removal
    rmmod dns_filter
