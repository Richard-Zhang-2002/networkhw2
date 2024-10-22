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

  printf("*** -> Received packet of length %d \n",len);

  /* fill in code here */
  
  //length sanity check, should at least contain an ip and ethernet header
  if(len < sizeof(sr_ethernet_hdr_t)+ sizeof(sr_ip_hdr_t)){
    fprintf(stderr, "Packet is too short");
    return;
  }

  //checksum sanity check
  sr_ip_hdr_t* ip_hdr =(sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
  uint16_t received_checksum = ip_hdr->ip_sum;
  ip_hdr->ip_sum = 0;// Reset for checksum calculation
  uint16_t calculated_checksum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
  if(received_checksum != calculated_checksum){
    fprintf(stderr, "wrong checksum");
    return;
  }
  ip_hdr->ip_sum = received_checksum;
  ip_hdr->ip_ttl--;//decrement ttl
  if(ip_hdr->ip_ttl <= 0){
    //expired
    //sr_send_icmp(sr, packet, interface, 11, 0);
    //TODO: send some ICMP message
    return;
  }

  //need to update checksum since ttl is modified
  ip_hdr->ip_sum = 0;
  ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

  struct sr_rt* dest = sr_find_lpm(sr, ip_hdr->ip_dst);
  if(!dest){//if we don't find any good place to send
    //TODO: send some ICMP message
    //sr_send_icmp(sr, packet, interface, 3, 0);  // Type 3: Destination Unreachable, Code 0: Net Unreachable
    return;
  }

} /* end sr_handlepacket */

//helper function to find longest prefix match
struct sr_rt* sr_find_lpm(struct sr_instance* sr, uint32_t ip_dst){
    struct sr_rt* rt_entry = sr->routing_table;
    struct sr_rt* longest_match = NULL;
    uint32_t longest_mask = 0;

    while(rt_entry){//go over 
      uint32_t rt_mask = rt_entry->mask.s_addr;
      uint32_t rt_dest = rt_entry->dest.s_addr;

      //firstly there must be a match
      if((ip_dst & rt_mask)==(rt_dest & rt_mask)){
        //then we stick to the longest match
        if(rt_mask > longest_mask){
          longest_match = rt_entry;
          longest_mask = rt_mask;
        }
      }

      rt_entry = rt_entry->next;// Move to the next routing table entry
    }
    return longest_match;
}


/* Add any additional helper methods here & don't forget to also declare
them in sr_router.h.

If you use any of these methods in sr_arpcache.c, you must also forward declare
them in sr_arpcache.h to avoid circular dependencies. Since sr_router
already imports sr_arpcache.h, sr_arpcache cannot import sr_router.h -KM */
