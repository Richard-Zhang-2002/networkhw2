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

  //printf("*** -> Received packet of length %d \n",len);

  /* fill in code here */

  sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t*) packet;

  //in case we are dealing with arp stuff
  if (ntohs(eth_hdr->ether_type) == ethertype_arp) {
    sr_arp_hdr_t* arp_hdr = (sr_arp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
    
    //go over my interfaces and see if any is the target
    struct sr_if* iface = sr->if_list;
    int found_interface = 0;
    while (iface) {
      if (iface->ip == arp_hdr->ar_tip) {
        found_interface = 1;
        break;  // We found a match, so stop looping
      }
      iface = iface->next;
    }

    //if the arp is targetting my router
    if(found_interface){
      if (ntohs(arp_hdr->ar_op) == arp_op_request) {//in case of handling request
        uint8_t* arp_reply = (uint8_t*) malloc(len);
        memcpy(arp_reply, packet, len);//modify the request to create our reply, they have similar structure anyway

        //header of the reply(ethernet and arp)
        sr_ethernet_hdr_t* eth_reply_hdr = (sr_ethernet_hdr_t*) arp_reply;
        sr_arp_hdr_t* arp_reply_hdr = (sr_arp_hdr_t*) (arp_reply + sizeof(sr_ethernet_hdr_t));

        //reverse sender and receiver desination in MAC
        memcpy(eth_reply_hdr->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
        memcpy(eth_reply_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);


        //handle arp header
        arp_reply_hdr->ar_op = htons(arp_op_reply);//we are not requesting but replying
        memcpy(arp_reply_hdr->ar_sha, iface->addr, ETHER_ADDR_LEN);//sender address is the address of this interface
        arp_reply_hdr->ar_sip = iface->ip;//similar to above, but IP instead of MAC
        memcpy(arp_reply_hdr->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN);//again, our target is the previous sender
        arp_reply_hdr->ar_tip = arp_hdr->ar_sip;//similar to above, but IP instead of MAC

        //send packet and free space
        //printf("send packet as handling request \n");
        sr_send_packet(sr, arp_reply, len, interface);
        free(arp_reply);
        return;
      }
      //in case of handling reply
      if (ntohs(arp_hdr->ar_op) == arp_op_reply) {
        pthread_mutex_lock(&sr->cache.lock);
        //get the request from the queue(also save the result to the cache)
        struct sr_arpreq* req = sr_arpcache_insert(&sr->cache, arp_hdr->ar_sha, arp_hdr->ar_sip);
        if (req) {//if there is an request, send all its packets and delete it
          struct sr_packet* packet_list = req->packets;
          while (packet_list) {
            sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t*) packet_list->buf;
            memcpy(eth_hdr->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);//destination should be the source of ARP(the one who responded to my IP to MAC request)
            memcpy(eth_hdr->ether_shost, sr_get_interface(sr, packet_list->iface)->addr, ETHER_ADDR_LEN);//we are sending from the router
            //printf("packet sent for handling reply\n");
            sr_send_packet(sr, packet_list->buf, packet_list->len, packet_list->iface);
            packet_list = packet_list->next;
          }
          sr_arpreq_destroy(&sr->cache, req);//delete the request after done(I think it handles delelting the packets by itself)
        }
        pthread_mutex_unlock(&sr->cache.lock);
        return;
      }
    }
    return;//don't resend arp anyway
  }
  
  //length sanity check, should at least contain an ip and ethernet header
  if(len < sizeof(sr_ethernet_hdr_t)+ sizeof(sr_ip_hdr_t)){
    fprintf(stderr, "Packet is too short");
    return;
  }

  //checksum sanity check
  sr_ip_hdr_t* ip_hdr =(sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
  uint16_t received_checksum = ip_hdr->ip_sum;
  ip_hdr->ip_sum = 0;// Reset for checksum calculation
  uint16_t calculated_checksum = cksum(ip_hdr, ip_hdr->ip_hl * 4);
  if(received_checksum != calculated_checksum){
    //fprintf(stderr, "wrong checksum");
    //fprintf(stderr, "Received checksum: 0x%04x\n", ntohs(received_checksum));  // Convert from network byte order for readability
    //fprintf(stderr, "Calculated checksum: 0x%04x\n", ntohs(calculated_checksum));  // Convert from network byte order for readability
    return;
  }

  struct sr_if* iface = sr->if_list;
  int is_for_router = 0;

  while (iface) {
    if (iface->ip == ip_hdr->ip_dst) {
      is_for_router = 1;
      break;//check if this message is for my router
    }
    iface = iface->next;
  }
  //if for me
  if (is_for_router) {
    if (ip_hdr->ip_p == ip_protocol_icmp) {//dealing with ping echo
      sr_icmp_hdr_t* icmp_hdr = (sr_icmp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
      if (icmp_hdr->icmp_type == 8 && icmp_hdr->icmp_code == 0) {//make sure it's actually an echo request
        sr_send_icmp(sr, packet, len, interface, 0, 0);
        return;
      }
    }else if (ip_hdr->ip_p == ip_protocol_tcp|| ip_hdr->ip_p == ip_protocol_udp) {
      sr_send_icmp(sr, packet, len, interface, 3, 3);//deal with TCP and UDP
    } else {
      //just ignore
    }
  }else{//not for me
    ip_hdr->ip_sum = received_checksum;
    ip_hdr->ip_ttl--;//decrement ttl
    if(ip_hdr->ip_ttl <= 0){//if timeout
      sr_send_icmp(sr, packet, len, interface, 11, 0);
      return;
    }

    //need to update checksum since ttl is modified
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = cksum(ip_hdr, ip_hdr->ip_hl * 4);

    struct sr_rt* dest = sr_find_lpm(sr, ip_hdr->ip_dst);
    if(!dest){//if we don't find any good place to send
      sr_send_icmp(sr, packet, len, interface, 3, 0);//destination unreachable
      return;
    }
    //see if this destination is saved in cache
    struct sr_arpentry* arp_entry = sr_arpcache_lookup(&sr->cache, dest->gw.s_addr);
    struct sr_if* out_iface = sr_get_interface(sr, dest->interface);
    if (arp_entry) {//if we can find it
      sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t*) packet;
      memcpy(eth_hdr->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);//destination mac is given by the cache
      memcpy(eth_hdr->ether_shost, out_iface->addr, ETHER_ADDR_LEN); //source mac is my outgoing port
      //printf("packet sent for handling finding something in cache\n");
      sr_send_packet(sr, packet, len, out_iface->name);
      free(arp_entry);
    } else {
      //not in the cache, so just add to the queue
      sr_arpcache_queuereq(&sr->cache, dest->gw.s_addr, packet, len, out_iface->name);//request will later be handled when I hear back from it
    }
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
