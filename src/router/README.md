# README for Assignment 2: Router

Name: Richard Zhang

JHED: rzhang89

---

Some guiding questions:
- What files did you modify (and why)?
- What helper method did you write (and why)?
- What logic did you implement in each file/method?
- What problems or challenges did you encounter?


**DESCRIBE YOUR CODE AND DESIGN DECISIONS HERE**

This will be worth 10% of the assignment grade.
I modified both sr_arpcahce and sr_router. They are modified because both included unimplemented functions that are key to the functionality of the router(the caching system and handling request). I also added the appropriate sr_ip_protocol enum for udp and tcp in sr_protocol.h file.

My workflow & logic is as the following: in sr_handlepacket, I first identify whether the packet is an arp. If so, in case of request, I respond to it if it is targetting any of my router's interfaces, otherwise the arp is simply ignored. In case of reply, I will read the mac address included in the reply and use it to send the related packages. Then I will also save the replied address in the cache for future use. If we are not handling an arp(so dealing with ip), I first check the length and the checksum of the input for correctness. Then if the message is sent toward one of my router's interfaces, I deal with it by reading the ip protocal and send icmp respectively(or not, if we are not asked for an echo and we are not getting UDP or TCP). In case the packet is not targetting one of my interfaces, I will first decrement ttl and recalculate checksum based on the modified ttl. Then I will try to fetch ip address in the routing table. If not found, send an icpm. If found, try to find the respective mac address in the cache. If found, send the packet. Otherwise, put the packet request into the queue and let the cache system handle it.

In the arpcache file, my sr_arpcache_sweepreqs simply handles all requests iteratively. My handle_arpreq will find the requests that were sent >= 5 times and destroy them(also send icmp respectively). For the requests that are still valid, we send out arp request as a broacast message to try fetching its MAC address. The reply is not listened in the arpcache but is received above by sr_handlepacket.

The helper functions I write are sr_send_icmp that sends an icmp with a particular type and code, this is particularly useful since I am often asked to send different kind of icmps. It is defined in arpcache so that both itself and my sr_router can use it to send icmps(as both need to send icmp at some step). I also implemented sr_find_lpm in sr_router. It essentially finds the longest prefix match of an ip in the routing table, and it is useful in case I want to forward the packet.

The major problem is to understand the problem and the starter code. Essentially, understanding what functionalities do we already have and what are we expected to implement in this project. It also takes time to understand the defined structs and functions to tell what they do and how should they be formatted. Lastly, the code is rather hard to debug in case of error since in many cases we do not know what the correct path/port/interface should be(since it's hard to read the routing table and do the calculation by hand), thus it is difficult to tell what our program is doing wrong at which step. In the end, I have to rely on reading my code back and forth many time and try to find the logical issue in the code itself since it is easier than examining the output.

Regarding testing, first call make to create the .sr file, then move the sr file to the appropriate folder(being src, essentially where sr_solution is). The folder I have itself can be placed anywhere, and it is the sz executable that matters. Then the testing procedure should follow the procedured provided in the assignment instrcution, but replacing sr_solution with sr. Please contact me if there is any issue with testing my file and I can demonstrate it in my environment, as I demonstrated it to one of the TAs and it works correctly.