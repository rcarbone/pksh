/*
 * pksh - The Packet Shell
 *
 * R. Carbone (rocco@tecsiel.it)
 * 2003, 2008-2009, 2022
 *
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Network interfaces protocol decoders for:
 *   * DLT_NULL (Loopback interface)
 *   * DLT_EN10MB (Ethernet 10Mb and up)
 */


/* System headers */
#if defined(linux)
# include <net/ethernet.h>
#endif

/* Project header */
#include "pksh.h"


/* The length of Ethernet Protocol header (14 bytes long) */
#define ETHERNET_HEADER sizeof (struct ether_header)

/* The header is only 4 bytes long in case of no link-layer encapsulation (DLT_NULL).
 * It contains a network order 32 bit integer that specifies the family, e.g. AF_INET */
#define LOOPBACK_HEADER 4


/* Ethernet address length in human readable format "xx:xx:xx:xx:xx:xx" */
#define ETHADDRLEN      18

/* Broadcast Ethernet address
 *
 * Ethernet frames can be addressed to every computer on a given LAN segment if they
 * are addressed to the MAC address ff:ff:ff:ff:ff:ff
 * (ARP typically uses broadcast queries)
 */
#define ETH_BROADCAST     "ff:ff:ff:ff:ff:ff"

#define MULTICAST_PREFIX  "33:33:"
#define MULTICAST_LEN     6
#define IGMP_PREFIX       "01:00:5e:"
#define IGMP_LEN          9


/* Some well known Multicast Ethernet addresses */
static char * eth_multicast [] =
{
  "01:00:0c:cc:cc:cc",  /* CDP (Cisco Discovery Protocol), VTP (Virtual Trunking Protocol) */
  "01:00:0c:cc:cc:cd",  /* Cisco Shared Spanning Tree Protocol Address                     */
  "01:80:c2:00:00:00",  /* Spanning Tree Protocol (for bridges) IEEE 802.1D                */
  "01:00:5e:xx:xx:xx",  /* IPv4 IGMP Multicast Address                                     */
  "33:33:00:00:00:00",  /* IPv6 Neighbor Discovery                                         */
  "33:33:00:xx:xx:xx",  /* IPv6 Multicast Address (RFC307)                                 */
  NULL
};


/* The table of known protocols over a given data-link (network interface) */
static protocol_t l2_protocols [] =
{
  { ETHERTYPE_IP,     ip   },
  { ETHERTYPE_ARP,    arp  },
  { ETHERTYPE_REVARP, rarp },
  { -1,               NULL },
};


/* Check if a parser exists for this protocol */
static protocol_t * l2_protocol (int id)
{
  protocol_t * p;

  for (p = l2_protocols; p -> counter; p ++)
    if (p -> id == id)
      return p;
  return NULL;
}


/* Check if an Ethernet address is a multicast address */
int multicast (char * addr)
{
  char ** a;

  for (a = eth_multicast; a && * a; a ++)
    if (! strncmp (addr, MULTICAST_PREFIX, MULTICAST_LEN) || ! strncmp (addr, IGMP_PREFIX, IGMP_LEN) || ! strcmp (* a, addr))
      return 1;
  return 0;
}


/* Stolen from tcpdump distribution (original in file addrtoname.c) */
static char hex [] = "0123456789abcdef";
char * mactoa (u_char * e)
{
  static char mac [ETHADDRLEN];

  char * p = mac;
  int i;

  for (i = 0; i < 6; i ++)
    {
      * p ++ = hex [* e >> 4];
      * p ++ = hex [* e ++ & 0xf];
      * p ++ = i < 5 ? ':' : '\0';
    }
  return mac;
}


/* Protocol decoder/counter for Ethernet interfaces
 *  Ethernet sizes
 *
 * The header is 14 bytes long - eg. sizeof (struct ether_header)
 */
void ethernet (interface_t * intf, struct pcap_pkthdr * h, const u_char * p)
{
  /* The Ethernet Protocol */
  struct ether_header * eth = (struct ether_header *) p;

  /* Header for the encapsulated protocols (IP, ARP, RARP, ...) */
  header_t header = { p, & h -> ts, h -> len - ETHERNET_HEADER, h -> caplen - ETHERNET_HEADER };

  char * addr;
  host_t * tx;
  host_t * rx = NULL;
  protocol_t * protocol;

  /* Update bytes and packets counters */
  intf -> headers_total += ETHERNET_HEADER;
  intf -> bytes_total += h -> len;
  intf -> pkts_total ++;

  /* Check for boundaries */
  if (h -> caplen < ETHERNET_HEADER)
    return;

  /* Get source Ethernet address and add it to the space of known HW names (if not already in) */
  tx = addtohwnames (intf, addr = mactoa ((u_char *) & eth -> ether_shost));

  /* Update bytes and packets counters for the transmitting TX equipment */
  tx -> bytes_sent += h -> len;
  tx -> pkts_sent ++;

  /* Update TX source Ethernet address and vendor name (if still missing) */
  if (! tx -> hwaddress)
    tx -> hwaddress = strdup (addr);
  resolvvendorname (tx);

  /* Get destination Ethernet address and lookup for Broadcast Ethernet address to avoid its inclusion to the space of known HW names */
  if (! strcmp (addr = mactoa ((u_char *) & eth -> ether_dhost), ETH_BROADCAST))
    {
      intf -> bytes_broadcast += h -> len;
      intf -> pkts_broadcast ++;
      tx -> bytes_broadcast += h -> len;
      tx -> pkts_broadcast ++;
    }
  else
    {
      /* Lookup for Multicast destination Ethernet address to avoid inclusion into hosts cache */
      if (multicast (addr))
	{
	  intf -> bytes_multicast += h -> len;
	  intf -> pkts_multicast ++;
	  tx -> bytes_multicast += h -> len;
	  tx -> pkts_multicast ++;
	}
      else
	{
	  /* Add destination Ethernet address to the space of known HW names (if not already in) */
	  rx = addtohwnames (intf, addr);

	  /* Update bytes and packets counters for the receiving RX equipment */
	  rx -> bytes_recv += h -> len;
	  rx -> pkts_recv ++;

	  /* Update RX destination Ethernet address and vendor name (if still missing) */
	  if (! rx -> hwaddress)
	    rx -> hwaddress = strdup (addr);
	  resolvvendorname (rx);
	}
    }

  /* Attempt to decode and count packets foreach known protocol id (IP, ARP, RARP, ...) */
  if ((protocol = l2_protocol (ntohs (eth -> ether_type))))
    protocol -> counter (intf, & header, (u_char *) eth + ETHERNET_HEADER, tx, rx);
  else
    intf -> bytes_non_ip += h -> len - ETHERNET_HEADER,
      intf -> pkts_non_ip ++;
}


/* Protocol decoder/counter for loopback interfaces */
void loopback (interface_t * intf, struct pcap_pkthdr * h, const u_char * p)
{
  /* Ethernet Protocol */
  struct ether_header * e = (struct ether_header *) p;

  /* Header for the encapsulated protocol (IP, ARP, RARP, ...) */
  header_t header = { p, & h -> ts, h -> len - LOOPBACK_HEADER, h -> caplen - LOOPBACK_HEADER };

  protocol_t * protocol;

  /* Add source loopback IP address into the IP space of known names (if not already in) */
  host_t * srchost = addtohwnames (intf, LOOPBACK_ADDR);

  /* Update counters */
  intf -> headers_total += LOOPBACK_HEADER;
  intf -> bytes_total += h -> len;
  intf -> pkts_total ++;

  /* Attempt to decode and count packets foreach known protocol id (IP, ARP, RARP, ...) */
  if ((protocol = l2_protocol (ntohs (e -> ether_type))))
    protocol -> counter (intf, & header, (u_char *) p + LOOPBACK_HEADER, srchost, NULL);
  else
    intf -> bytes_non_ip += h -> len - LOOPBACK_HEADER,
      intf -> pkts_non_ip ++;
}
