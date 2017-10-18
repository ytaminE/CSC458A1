/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance *sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);

    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance *sr,
                     uint8_t *packet /* lent */,
                     unsigned int len,
                     char *interface /* lent */) {
    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);

    printf("*** -> Received packet of length %d \n", len);

    /* fill in code here */

    /* Handle the ARP or IP packet*/
    if (ethertype(packet) == ethertype_arp) {
        printf("This is an ARP packet\n");
        /* print_hdr_eth(packet); */
        sr_handleARPPacket(sr, packet, len, interface);
        return;
    } else if (ethertype(packet) == ethertype_ip) {
        printf("This is an IP packet\n");
        /* print_hdr_eth(packet);  */
        sr_handleIPPacket(sr, packet, len, interface);
        return;
    } else {
        fprintf(stderr, "The packet received is neither ARP packet or IP packet\n");
        return;
    }

} /* end sr_ForwardPacket */

void sr_handleARPPacket(struct sr_instance *sr, uint8_t *packet /* lent */, unsigned int len, char *interface /* lent */)
{
    printf("*** -> Start handling ARP packet\n");
    
    /* Sanity check*/
    if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t)) {
        fprintf(stderr, "The length of this ARP packet is less than the required number\n");
        return;
    }
    /* Extract ethernet header */
    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;

    /* Extract ARP header */
    sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)((unsigned char *)packet + sizeof(sr_ethernet_hdr_t));

    /* Extract ARP opcode (command) */
    unsigned short ar_op = ntohs(arp_hdr->ar_op);

    struct sr_if *ingoing_interface = sr_get_interface(sr, interface);

    if(ingoing_interface->ip == arp_hdr->ar_tip) {
        /* If this packet is destined to me(the router) */
        if (ar_op == arp_op_request) {
            /* If it is an ARP request */
            printf("This is an ARP request\n");

            /* Update the ethernet header */
            sr_ethernet_hdr_t *new_eth_hdr = (sr_ethernet_hdr_t *)malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
            construct_ETHERNET_header(eth_hdr, new_eth_hdr, ingoing_interface);                

            /* Create the ARP reply header */
            sr_arp_hdr_t *new_arp_hdr = (sr_arp_hdr_t *)((unsigned char *)new_eth_hdr + sizeof(sr_ethernet_hdr_t));
            construct_ARP_header(arp_hdr, new_arp_hdr, ingoing_interface);

            /*Start sending ARP reply  */
            sr_send_packet(sr, (uint8_t *)new_eth_hdr, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t), ingoing_interface->name);
            free(new_eth_hdr);
            return;
        } else if (ar_op == arp_op_reply) {
            /* If it is an ARP reply */

            /* Cache */
            struct sr_arpcache *cache = &(sr->cache);
            struct sr_arpreq *arp_request = sr_arpcache_insert(cache, arp_hdr->ar_sha, arp_hdr->ar_sip);

            if (arp_request) {
                struct sr_packet *packet = arp_request->packets;
                /* Send all the outstanding packets in the ARP queue. */
                while (packet != NULL) {
                    /* Ethernet header of the packet */
                    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)(packet->buf);
                    /* The outgoing interface of the packet*/
                    struct sr_if *packet_interface = sr_get_interface(sr, packet->iface);
                    memcpy(eth_hdr->ether_shost, packet_interface->addr, ETHER_ADDR_LEN);
                    memcpy(eth_hdr->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
                    /* Send the packet */
                    sr_send_packet(sr, packet->buf, packet->len, packet_interface->name);
                    packet = packet->next;
                }
                sr_arpreq_destroy(cache, arp_request);
            } 
        } else {
            printf("Neither APR request or ARP reply");
        }
    }
    return;
}

void sr_handleIPPacket(struct sr_instance *sr, uint8_t *packet /* lent */, unsigned int len, char *interface /* lent */) {

    /* Sanity check*/
    if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) {
        fprintf(stderr, "The length of this IP packet is less than the required number\n");
        return;
    }

    fprintf(stderr, "Start handling IP packet\n");
    /* Extract ethernet header */
    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;

    /* Extract IP header */
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)((unsigned char *)packet + sizeof(sr_ethernet_hdr_t));
    
    /* Check the IP version */
    if(ip_hdr->ip_v != 4) {
        printf("This IP packet is not IPV4\n");
        return;
    }
    /* Validate the checksum */
    if (!cksum(ip_hdr, sizeof(sr_ip_hdr_t)) == ip_hdr->ip_sum) {
        printf("The checksum in this IP packet is not correct!\n");
        return;
    }
    
    /* ARP cache */
    struct sr_arpcache *sr_arp_cache = &sr->cache;
    struct sr_if *cur_if = sr_get_interface(sr, interface);

/*     struct sr_if *dst_if = look_for_interface(sr, ip_hdr->ip_dst);
 */    /* Check whether the packet is sent to a router's interfacee */
    uint32_t ip = ip_hdr->ip_dst;
    struct sr_if *dst_if = 0;
    struct sr_if *if_list = sr->if_list;
    while (if_list) {
        if (if_list->ip == ip) {
            dst_if = if_list;
        }
        if_list = if_list->next;
    }

    /* If this packet is destined to the router */
    if (ip_hdr -> ip_p == ip_protocol_icmp) {
        print_hdrs(packet,sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t) );
    }

    if (dst_if) {
        /* If it is an ICMP echo */
        if (ip_hdr -> ip_p == ip_protocol_icmp) {
            /* Get the icmp header */
            sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)((unsigned char *)packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
            /* If it is an Echo (type = 8), the router wil send an Echo Reply with type 0 and code 0 */
            if (icmp_hdr->icmp_type == 8) {
                struct sr_rt *lpm_rt = sr_lpm(sr, ip_hdr->ip_src);
                if (lpm_rt) {
                    /* Check the ARP cache  */
                    struct sr_arpentry *entry = sr_arpcache_lookup(&sr->cache, lpm_rt->gw.s_addr);
                    struct sr_if *lpm_if = sr_get_interface(sr, lpm_rt->interface);
                    if (entry) {
                        sendICMPEchoReply(sr, lpm_if, packet, len, eth_hdr, ip_hdr, icmp_hdr);
                        free(entry);
                        return;
                    } else {
                        /* Add reply to the ARP queue */
                        enqueueICMPEchoReply(sr, lpm_if, packet, len, eth_hdr, ip_hdr, icmp_hdr);
                        return;
                    }
                } else {
                    fprintf(stderr, "No longest prefix found\n");
                    return;
                }
            } else {
                fprintf(stderr, "Not an ICMP Echo (type 8)!\n");
                return;
            }
        } else {            
            /* Handle the TCP/UDP request */
            /* Do LPM on the routing table */
            /* Check the routing table and see if the incoming ip matches the routing table ip, and find LPM router entry */
            struct sr_rt *lpm_rt = sr_lpm(sr, ip_hdr->ip_src);
            if (lpm_rt) {
                struct sr_arpentry *entry = sr_arpcache_lookup(&sr->cache, lpm_rt->gw.s_addr);             
                /* Send ICMP port unreachable */
                if (entry) {
                    sendICMPPacket(sr, cur_if, eth_hdr, ip_hdr, 3, 3);
                    free(entry);
                    return;
                } else {
                    enqueueICMPPacket(sr, cur_if, eth_hdr, ip_hdr, 3, 3);
                    return;
                }
            } else {
                fprintf(stderr, "No longest prefix found\n");
                return;
            }
        }
    } else {
        /* If this packet is not destined to the router */
        /* Check the TTL */
        if (ip_hdr->ip_ttl <= 1) {
            /* Send ICMP packett */
            struct sr_arpentry *entry = sr_arpcache_lookup(sr_arp_cache, ip_hdr->ip_src);
            if (entry) {
                sendICMPPacket(sr, cur_if, eth_hdr, ip_hdr, 11, 0);
                free(entry);
            } else {
                enqueueICMPPacket(sr, cur_if, eth_hdr, ip_hdr, 11, 0);
            }
            return;
        }
        /* Look up next-hop address with LPM */
        struct sr_rt *lpm_dst = sr_lpm(sr, ip_hdr->ip_dst);
        
        if (lpm_dst) {
            /* Check ARP cache */
            struct sr_if *lpm_if = sr_get_interface(sr, lpm_dst->interface);
            struct sr_arpentry *entry = sr_arpcache_lookup(&sr->cache, lpm_dst->gw.s_addr);
            /* Reduce TTL */
            ip_hdr->ip_ttl--;
            /* Update the checksum */
            ip_hdr->ip_sum = 0;
            uint16_t new_ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
            ip_hdr->ip_sum = new_ip_sum;
            if (entry) {
                memcpy(eth_hdr->ether_shost, lpm_if->addr, ETHER_ADDR_LEN);
                memcpy(eth_hdr->ether_dhost, entry->mac, ETHER_ADDR_LEN);
                /* Send the packet */
                sr_send_packet(sr, packet, len, lpm_if->name);
                free(entry);
                return;
            } else {
                /* Send ARP request to get the MAC address */
                struct sr_arpreq *arp_req = sr_arpcache_queuereq(sr_arp_cache, ip_hdr->ip_dst, packet, len, lpm_if->name);
                handle_arpreq(arp_req, sr);
                return;
            }
        } else {
            /* If lpm doesn't exist, send ICMP net unreachable type 3 code 0 */
            struct sr_rt *lpm_src = sr_lpm(sr, ip_hdr->ip_src);
            if (lpm_src) {
                /* check ARP cache */
                struct sr_arpentry *entry = sr_arpcache_lookup(&sr->cache, lpm_src->gw.s_addr);
                if (entry) {
                    sendICMPPacket(sr, cur_if, eth_hdr, ip_hdr, 3, 0);
                    free(entry);
                    return;
                } else {
                    enqueueICMPPacket(sr, cur_if, eth_hdr, ip_hdr, 3, 0);
                    return;
                }
            } else {
                fprintf(stderr, "No longest prefix found for ip_src\n");
                return;
            }
        }
    }
    return;
}

/* Find the longest prefix match */
struct sr_rt *sr_lpm(struct sr_instance *sr, uint32_t ip) {

    struct sr_rt *table = sr->routing_table;
    uint32_t max_len = 0;
    struct sr_rt *res = NULL;
    /* Go over all the ip in the routing table and find the longest prefix match  */
    while (table) {
        if ((ip & table->mask.s_addr) == (table->dest.s_addr & table->mask.s_addr)) {
            if (max_len < table->mask.s_addr) {
                max_len = table->mask.s_addr;
                res = table;
            }
        }
        table = table->next;
    }
    return res;
}

void enqueueICMPEchoReply(struct sr_instance *sr, struct sr_if *lpm_if, uint8_t *packet, unsigned int len, sr_ethernet_hdr_t *eth_hdr, sr_ip_hdr_t *ip_hdr, sr_icmp_hdr_t *icmp_hdr) {
    
    struct sr_arpcache *sr_arp_cache = &sr->cache;
        
    memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
    memcpy(eth_hdr->ether_shost, lpm_if->addr, ETHER_ADDR_LEN);

    ip_hdr->ip_off = htons(0b0100000000000000);
    ip_hdr->ip_ttl = 64;
    uint32_t temp = ip_hdr->ip_src;
    ip_hdr->ip_src = ip_hdr->ip_dst;
    ip_hdr->ip_dst = temp;
    ip_hdr->ip_sum = 0;
    uint16_t new_ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
    ip_hdr->ip_sum = new_ip_sum;

    icmp_hdr->icmp_type = 0;
    icmp_hdr->icmp_code = 0;
    icmp_hdr->icmp_sum = 0;
    uint16_t new_icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_t3_hdr_t));
    icmp_hdr->icmp_sum = new_icmp_sum;
    struct sr_arpreq *arp_req = sr_arpcache_queuereq(sr_arp_cache, ip_hdr->ip_dst, packet, len, lpm_if->name);
    handle_arpreq(arp_req, sr);
}
void sendICMPEchoReply(struct sr_instance *sr, struct sr_if *lpm_if, uint8_t *packet, unsigned int len, sr_ethernet_hdr_t *eth_hdr, sr_ip_hdr_t *ip_hdr, sr_icmp_hdr_t *icmp_hdr) {
    
    memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
    memcpy(eth_hdr->ether_shost, lpm_if->addr, ETHER_ADDR_LEN);

    ip_hdr->ip_off = htons(0b0100000000000000);
    ip_hdr->ip_ttl = 64;
    uint32_t temp = ip_hdr->ip_src;
    ip_hdr->ip_src = ip_hdr->ip_dst;
    ip_hdr->ip_dst = temp;
    ip_hdr->ip_sum = 0;
    uint16_t new_ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
    ip_hdr->ip_sum = new_ip_sum;

/*  unsigned int icmp_size = len - sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t);*/
    icmp_hdr->icmp_type = 0;
    icmp_hdr->icmp_code = 0;
    icmp_hdr->icmp_sum = 0;
    uint16_t new_icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_t3_hdr_t));
    icmp_hdr->icmp_sum = new_icmp_sum;
    /* Send icmp echo reply */
    sr_send_packet(sr, packet, len, lpm_if->name);
}
void enqueueICMPPacket(struct sr_instance *sr, struct sr_if *cur_if, sr_ethernet_hdr_t *eth_hdr, sr_ip_hdr_t *ip_hdr, uint8_t type ,uint8_t code) {
    /* Construct the ICMP packet */
    int ICMP_LENGTH = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
    uint8_t *icmp_packet = (uint8_t *)malloc(ICMP_LENGTH);
    struct sr_arpcache *sr_arp_cache = &sr->cache;
    
    /* Construct the Ethernet header */
    sr_ethernet_hdr_t *new_eth_hdr = (sr_ethernet_hdr_t *)icmp_packet;
    construct_ETHERNET_header(eth_hdr, new_eth_hdr, cur_if);                    

    /* Construct the IP header */
    sr_ip_hdr_t *new_ip_hdr = (sr_ip_hdr_t *)((unsigned char *)icmp_packet + sizeof(sr_ethernet_hdr_t));
    construct_IP_header(ip_hdr, new_ip_hdr, cur_if);                    

    /* Construct ICMP header with type 3 code 3*/
    sr_icmp_t3_hdr_t *icmp_hdr = (sr_icmp_t3_hdr_t *)((unsigned char *)icmp_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    construct_ICMP_header(ip_hdr, icmp_hdr, type, code);                    

    struct sr_arpreq *arp_req = sr_arpcache_queuereq(sr_arp_cache, ip_hdr->ip_src, icmp_packet, ICMP_LENGTH, cur_if->name);
    handle_arpreq(arp_req, sr);

}
    
void sendICMPPacket(struct sr_instance *sr, struct sr_if *cur_if, sr_ethernet_hdr_t *eth_hdr, sr_ip_hdr_t *ip_hdr, uint8_t type ,uint8_t code) {
    int ICMP_LENGTH = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
    uint8_t *icmp_packet = (uint8_t *)malloc(ICMP_LENGTH);

    /* Construct the Ethernet header */
    sr_ethernet_hdr_t *new_eth_hdr = (sr_ethernet_hdr_t *)icmp_packet;                
    construct_ETHERNET_header(eth_hdr, new_eth_hdr, cur_if);                      

    /* Construct the IP header */
    sr_ip_hdr_t *new_ip_hdr = (sr_ip_hdr_t *)((unsigned char *)icmp_packet + sizeof(sr_ethernet_hdr_t));
    construct_IP_header(ip_hdr, new_ip_hdr, cur_if);

    /* Construct ICMP header with type 3 code 3 */
    sr_icmp_t3_hdr_t *icmp_hdr = (sr_icmp_t3_hdr_t *)((unsigned char *)icmp_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    construct_ICMP_header(ip_hdr, icmp_hdr, type, code);                        
/*     print_hdrs(icmp_packet, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t) );
 */    /* Send ICMP packet */
    sr_send_packet(sr, icmp_packet, ICMP_LENGTH, cur_if->name);
    free(icmp_packet);
}

void construct_ARP_header(sr_arp_hdr_t *arp_hdr, sr_arp_hdr_t *arp_reply, struct sr_if *cur_if) {
    arp_reply->ar_hrd = arp_hdr->ar_hrd;
    arp_reply->ar_hrd = arp_hdr->ar_hrd;
    arp_reply->ar_pro = arp_hdr->ar_pro;
    arp_reply->ar_hln = arp_hdr->ar_hln;
    arp_reply->ar_pln = arp_hdr->ar_pln;
    arp_reply->ar_op = htons(arp_op_reply);
    arp_reply->ar_tip = arp_hdr->ar_sip;
    arp_reply->ar_sip = cur_if->ip;
    memcpy(arp_reply->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN);
    memcpy(arp_reply->ar_sha, cur_if->addr, ETHER_ADDR_LEN);
}

void construct_ICMP_header(sr_ip_hdr_t *ip_hdr, sr_icmp_t3_hdr_t *icmp_hdr, uint8_t type, uint8_t code) {
    
    icmp_hdr->icmp_type = type;
    icmp_hdr->icmp_code = code;
    icmp_hdr->unused = 0;
    icmp_hdr->next_mtu = 0;
    memcpy(icmp_hdr->data, ip_hdr, ICMP_DATA_SIZE);
    icmp_hdr->icmp_sum = 0;
    uint16_t new_icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_t3_hdr_t));
    icmp_hdr->icmp_sum = new_icmp_sum;
}

void construct_ETHERNET_header(sr_ethernet_hdr_t *eth_hdr, sr_ethernet_hdr_t *new_eth_hdr, struct sr_if *cur_if) {
    memcpy(new_eth_hdr->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
    memcpy(new_eth_hdr->ether_shost, cur_if->addr, ETHER_ADDR_LEN);
    new_eth_hdr->ether_type = eth_hdr->ether_type;
}


void construct_IP_header(sr_ip_hdr_t *ip_hdr, sr_ip_hdr_t *new_ip_hdr, struct sr_if *cur_if) {
    new_ip_hdr->ip_hl = ip_hdr->ip_hl;
    new_ip_hdr->ip_v = ip_hdr->ip_v;
    new_ip_hdr->ip_tos = ip_hdr->ip_tos;
    new_ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
    new_ip_hdr->ip_id = 0;
    new_ip_hdr->ip_off = htons(0b0100000000000000);
    new_ip_hdr->ip_off = 0;    
    new_ip_hdr->ip_ttl = 64;
    new_ip_hdr->ip_p = ip_protocol_icmp;
    new_ip_hdr->ip_src = cur_if->ip;
    new_ip_hdr->ip_dst = ip_hdr->ip_src;
    new_ip_hdr->ip_sum = 0;
    uint16_t new_ip_sum = cksum(new_ip_hdr, sizeof(sr_ip_hdr_t));
    new_ip_hdr->ip_sum = new_ip_sum;
}