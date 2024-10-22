/**********************************************************************
 * file:  sr_router.c
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
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

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

void sr_init(struct sr_instance* sr)
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

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);

    printf("*** -> Received packet of length %d \n", len);

    /* Step 1: Sanity check - ensure packet is at least the length of an Ethernet header */
    if (len < sizeof(sr_ethernet_hdr_t)) {
        fprintf(stderr, "Packet is too short to be valid Ethernet frame.\n");
        return;
    }

    /* Step 2: Parse Ethernet header */
    sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t*) packet;

    /* Step 3: Check if it's an ARP packet */
    if (ntohs(eth_hdr->ether_type) == ethertype_arp) {
        /* Handle ARP request/reply */
        sr_handle_arp_packet(sr, packet, len, interface);  // Function defined in sr_arpcache.c
        return;
    }

    /* Step 4: Check if it's an IP packet */
    if (ntohs(eth_hdr->ether_type) == ethertype_ip) {
        /* Ensure packet has at least the IP header length */
        if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) {
            fprintf(stderr, "Packet too short to contain valid IP header.\n");
            return;
        }

        /* Extract IP header */
        sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));

        /* Step 5: Verify IP checksum */
        uint16_t checksum = ip_hdr->ip_sum;
        ip_hdr->ip_sum = 0;  // Set checksum to 0 for recalculation
        if (checksum != cksum(ip_hdr, sizeof(sr_ip_hdr_t))) {  // cksum is defined in sr_utils.c
            fprintf(stderr, "Invalid IP checksum.\n");
            return;
        }
        ip_hdr->ip_sum = checksum;  // Restore the original checksum

        /* Step 6: Check if the packet is for one of the router's interfaces */
        struct sr_if* iface = sr_get_interface(sr, interface);  // Function defined in sr_if.c
        if (iface && iface->ip == ip_hdr->ip_dst) {
            /* Handle ICMP packets (ping) */
            if (ip_hdr->ip_p == ip_protocol_icmp) {
                sr_handle_icmp_echo(sr, packet, len, interface);  // ICMP Echo Reply
            }
            return;
        }

        /* Step 7: TTL and forwarding */
        if (ip_hdr->ip_ttl <= 1) {
            /* TTL expired, send ICMP Time Exceeded message */
            sr_send_icmp_ttl_expired(sr, packet, len, interface);  // Implement this helper
            return;
        }

        /* Decrement TTL and recompute checksum */
        ip_hdr->ip_ttl--;
        ip_hdr->ip_sum = 0;
        ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

        /* Step 8: Perform Longest Prefix Match (LPM) to find next hop */
        struct sr_rt* rt_entry = sr_find_lpm(sr, ip_hdr->ip_dst);  // Function to implement below
        if (!rt_entry) {
            /* No route found, send ICMP Destination Net Unreachable */
            sr_send_icmp_dest_unreachable(sr, packet, len, interface);  // Implement this helper
            return;
        }

        /* Step 9: Check ARP cache for next-hop MAC address */
        struct sr_arpentry* arp_entry = sr_arpcache_lookup(&sr->cache, rt_entry->gw.s_addr);  // Defined in sr_arpcache.c
        if (arp_entry) {
            /* Found ARP entry, forward the packet */
            sr_forward_packet(sr, packet, len, rt_entry->interface, arp_entry->mac);  // Implement this helper
            free(arp_entry);
        } else {
            /* ARP entry not found, queue packet and send ARP request */
            sr_arpcache_queuereq(&sr->cache, rt_entry->gw.s_addr, packet, len, rt_entry->interface);  // Defined in sr_arpcache.c
        }
    }
}



/* Add any additional helper methods here & don't forget to also declare
them in sr_router.h.

If you use any of these methods in sr_arpcache.c, you must also forward declare
them in sr_arpcache.h to avoid circular dependencies. Since sr_router
already imports sr_arpcache.h, sr_arpcache cannot import sr_router.h -KM */
