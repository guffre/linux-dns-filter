#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/netfilter_ipv4.h>
#include <linux/version.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Guffre");
MODULE_DESCRIPTION("DNS Filter");

static struct nf_hook_ops netfilter_hook_output;	// Struct holding set of hook function options

//DNS struct
struct dnshdr
{
    __be16 ident;
    __be16 flags;
    __be16 question_count;
    __be16 answer_rr_count;
    __be16 authority_rr_count;
    __be16 additional_rr_count;
};

/* nf_register_hook not available in newer Linux kernels */
void netfilter_hook(struct nf_hook_ops *reg)
{
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
        nf_register_net_hook(&init_net, reg);
    #else
        nf_register_hook(reg);
    #endif  
}

void netfilter_unhook(struct nf_hook_ops *reg)
{
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
        nf_unregister_net_hook(&init_net, reg);
    #else
        nf_unregister_hook(reg);
    #endif  
}

// netfilter hook function; called as packets exit the device
unsigned int block_dns(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct iphdr *ip_header = NULL;
    struct tcphdr *tcp_header = NULL;
    struct udphdr *udp_header = NULL;
    unsigned char *data_start;
    
    // Get the IP header out of the sk_buffer
    ip_header = (struct iphdr*)skb_network_header(skb);
    if (ip_header->protocol == IPPROTO_TCP)
    {
        // Get the TCP header
        tcp_header = (struct tcphdr*)skb_transport_header(skb);
        if (ntohs(tcp_header->dest) == 53)
        {
            // Get the address of the start of the TCP data section
            data_start = (unsigned char *)((void *)tcp_header + (int)(tcp_header->doff * 4));
            if (ntohs(((struct dnshdr*)(data_start))->flags) == 0x100)
            {
                printk(KERN_INFO "[+] DNS Request blocked!\n");
                return NF_DROP;
            }
        }
    }
    else if (ip_header->protocol == IPPROTO_UDP)
    {
        // Get the UDP header
        udp_header = (struct udphdr*)skb_transport_header(skb);
        if (ntohs(udp_header->dest) == 53)
        {
            // Get the address of the start of the UDP data section
            data_start = (unsigned char *)((void *)udp_header + 8);
            if (ntohs(((struct dnshdr*)(data_start))->flags) == 0x100)
            {
                printk(KERN_INFO "[+] DNS Request blocked!\n");
                return NF_DROP;
            }
        }
    }
	return NF_ACCEPT;
}

// Module load -  Start the DNS filter
static int __init start_dns_filter(void)
{
	// Configure netfilter hook
	netfilter_hook_output.hook      = block_dns;
	netfilter_hook_output.hooknum   = NF_INET_LOCAL_OUT;
	netfilter_hook_output.pf        = PF_INET;
	netfilter_hook_output.priority  = NF_IP_PRI_FIRST;
	
    // Register hook
    netfilter_hook(&netfilter_hook_output);

   	printk(KERN_INFO "[+} DNS Filter Inserted\n");
	return 0;
}

// Module Unload - Stop the DNS filter
static void __exit stop_dns_filter(void)
{
    // Unregister hook
	netfilter_unhook(&netfilter_hook_output);
	printk(KERN_INFO "[+} DNS Filter Removed\n");
}

module_init(start_dns_filter);
module_exit(stop_dns_filter);
