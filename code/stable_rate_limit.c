#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/netdevice.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <linux/netfilter_ipv4.h>
#include <linux/jiffies.h>


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Peter Chung");
MODULE_VERSION("1.0");
MODULE_DESCRIPTION("A Packet filtering module with flow control");

static int port = 80; 
MODULE_PARM_DESC(port, "Port number to limit, default is port 80");
module_param(port, int, 0644);

/*
static int pcount = 1000;
MODULE_PARM_DESC(pcount, "total packets to allow before dropping, default is 1000");
module_param(pcount, int, 0644);
*/

static int rate = 2000;
MODULE_PARM_DESC(rate, "Target rate in bytes/ms, default(min) is 2000");
module_param(rate, int, 0644);

static struct nf_hook_ops nfho_incoming;  // Hook struct at pre-routing

static unsigned long timeout = 0;
static unsigned long start = 0;
static int expect_total_payload = 0; 
/*
static unsigned long old_jiffies = 0;
static unsigned long ticks;
*/
/* Part 2 - Flow struct defintion */
struct Flow {
	unsigned int local_ip;
	unsigned int remote_ip;
	unsigned short int local_port;
	unsigned short int remote_port;
	// statistics
	unsigned int pktcount, dropcount, bytecount, bytedropcount; 
};
// SIZE = 1 << 12 = 4096
#define SIZE (1<<12)
static struct Flow flist[SIZE];

static inline unsigned int hash(struct Flow* f) {
    // a simple hash function, given a Flow struct (non-NULL), return a value in [0,SIZE-1]=1
    return ( (f->local_ip%SIZE+1) * (f->remote_ip%SIZE+1) * ( f->local_port%SIZE+1) * (f->remote_port%SIZE+1) )%SIZE;
}

static inline void reset_flow(struct Flow* f) {
    // assumption: f is non-NULL
    f->local_port = f->remote_port = 0;
    f->local_ip = f->remote_ip = 0;
    f->pktcount=f->dropcount=f->bytecount=f->bytedropcount=0;
}

/* Part 3 - The hook function */
static unsigned int hook_func_in(unsigned int hooknum, struct sk_buff *skb, 
                            const struct net_device *in, const struct net_device *out, 
                          int (*okfn)(struct sk_buff *)) {

    struct iphdr *ip_header;          // IP header structure
    struct tcphdr *tcp_header;        // TCP header structure
    struct ethhdr *eth_header;        // Ethernet Header
    unsigned int sIP, dIP;	      // IP addresses
    unsigned int sport, dport;        // Source and Destination port

    struct Flow f ;                   // a local flow struct 
    struct Flow *flow;                // a pointer (to be pointed)
    unsigned int payload_len;	      // TCP payload length

    // Get the eth_header by pointer arthematics
    eth_header = (struct ethhdr *)skb_mac_header(skb); 

    // The packet does not have an ethernet header
    if(!eth_header || (eth_header && eth_header->h_proto != __constant_htons(ETH_P_IP))) {
	//printk(KERN_INFO "[ACCEPT] Other packets\n");
        return NF_ACCEPT;
    }

    // Get the ip_header by pointer arthematics
    ip_header=(struct iphdr *)skb_network_header(skb);

    // The packet is not a IP packet 
    if (!ip_header) {
	//printk(KERN_INFO "[ACCEPT] Other packets\n");
        return NF_ACCEPT;
    }

    // A TCP packet
    if(ip_header->protocol==IPPROTO_TCP) {
	tcp_header = (struct tcphdr *)((__u32 *)ip_header+ ip_header->ihl);
	sIP = (unsigned int) ip_header->saddr;
	dIP = (unsigned int) ip_header->daddr;
	sport = ntohs((unsigned short int) tcp_header->source);
	dport = ntohs((unsigned short int) tcp_header->dest); 
 	if( sport != port && dport != port) {
	    //printk(KERN_INFO "[ACCEPT] TCP - Src:%pI4:%d, Dest:%pI4:%d\n", &sIP, sport, &dIP, dport);
            return NF_ACCEPT;
	}

	// Calculate the payload length
        payload_len= (unsigned int)ntohs(ip_header->tot_len)
                                -(ip_header->ihl<<2)
                                -(tcp_header->doff<<2);


        // reset a local flow struct
        // Note: source and estination should be changed
        reset_flow(&f);
	f.local_ip = dIP;
	f.remote_ip = sIP;
	f.local_port = dport;
	f.remote_port = sport;

	// Hash to find the flow index within the global array
	flow = &flist[ hash(&f) ]; 

	if ( tcp_header->fin) {
		printk(KERN_INFO "[Finish rate=%d] t=%lu ms, receive/drop(bytes): %u/%u\n",
				rate, (jiffies - start) * ((10000/HZ)/10), flow->bytecount, flow->bytedropcount);
		reset_flow(flow);
	}
	if ( payload_len <= 0)
		return NF_ACCEPT;
	
	
	if(start == 0) start = jiffies;
	

	if(time_before(jiffies, timeout)){	
		if(expect_total_payload <= 0){
			
			flow->dropcount++;
			flow->bytedropcount += payload_len;
					
			return NF_DROP;
		}else{		
			flow->pktcount++;
			flow->bytecount += payload_len;
			expect_total_payload -= payload_len;
			return NF_ACCEPT;
		}
	}else{
		timeout = jiffies + HZ;
		expect_total_payload = 1650 * rate;
		
		flow->pktcount++;
		flow->bytecount += payload_len;
		expect_total_payload -= payload_len;
		
		
		return NF_ACCEPT;
	}

    }
    //printk(KERN_INFO "[ACCEPT] TCP \n");
    return NF_ACCEPT;
}

/* Part 4 - Initialize and clean up the module */
int init_module(void) {
	int i;
	for (i=0; i<SIZE; i++)
		reset_flow(&flist[i]);

	nfho_incoming.hook = hook_func_in; 			// Setup the hook function
	nfho_incoming.hooknum = NF_INET_PRE_ROUTING;		// pre-routing
    	nfho_incoming.pf = PF_INET;				// IPV4 packets
    	nfho_incoming.priority = NF_IP_PRI_FIRST;		// set to the highest priority 
    	nf_register_hook(&nfho_incoming);			// register hook
    	return 0;
}

void cleanup_module(void) {
    nf_unregister_hook(&nfho_incoming);
}
