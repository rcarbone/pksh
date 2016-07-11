/*
 * decoders.c - Decoders/counters for the most common protocols
 *
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
 *                    _        _
 *              _ __ | | _____| |__
 *             | '_ \| |/ / __| '_ \
 *             | |_) |   <\__ \ | | |
 *             | .__/|_|\_\___/_| |_|
 *             |_|
 *
 *            'pksh', the Packet Shell
 *
 *            (C) Copyright 2003-2009
 *   Rocco Carbone <rocco /at/ ntop /dot/ org>
 *
 * Released under the terms of GNU General Public License
 * at version 3;  see included COPYING file for details
 *
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
 */


/* Operating System header file(s) */
#include <sys/types.h>
#include <arpa/inet.h>
#include <netdb.h>
#if defined(linux)
# if !defined(__FAVOR_BSD)
#  define __FAVOR_BSD
# endif
#endif
#include <netinet/tcp.h>

/* Private header file(s) */
#include "pksh.h"


/* The length of IP Protocol header (often 20 bytes long) */
#define IP_HEADER(x)    (x -> ip_hl * 4)

/* The length of TCP Protocol header (often 20 bytes long) */
#define TCP_HEADER(x)   (x -> th_off * 4)


/* The table of known IP protocols over known data-link types */
static protocol_t ip_protocols [] =
{
  { IPPROTO_ICMP, icmp },
  { IPPROTO_TCP,  tcp  },
  { IPPROTO_UDP,  udp  },
  { -1,           NULL },
};


/* The table of known TCP protocols over known IP Protocols */
static protocol_t tcp_protocols [] =
{
  { 80, http },
  { 25, smtp  },
  { -1, NULL },
};


/* Check if a parser exists for this IP protocol */
static protocol_t * ip_protocol (int id)
{
  protocol_t * p;

  for (p = ip_protocols; p -> counter; p ++)
    if (p -> id == id)
      return p;
  return NULL;
}


/* Check if a parser exists for this TCP protocol */
static protocol_t * tcp_protocol (int id)
{
  protocol_t * p;

  for (p = tcp_protocols; p -> counter; p ++)
    if (p -> id == id)
      return p;
  return NULL;
}


/* Access to the vendor hash table to resolve vendor name (if not already in) */
void resolvvendorname (host_t * h)
{
  if (h && ! h -> vendor)
    h -> vendor = vendor (h -> hwaddress);
}


/* Attempt to resolve hostname (if not already in) */
static void resolvhostname (host_t * h)
{
  struct hostent * host = NULL;
  struct in_addr ip;

  if (h && h -> ipaddr && ! h -> hostname && strcmp (inet_ntoa (h -> ip), NULL_IPADDR))
    inet_aton (h -> ipaddr, & ip),
      host = gethostbyaddr ((char *) & ip, sizeof (ip), AF_INET),
      h -> hostname = strdup (host ? host -> h_name : h -> ipaddr),
      bindtohostnames (h -> intf, h -> hostname, h);
}


/* Round the TTL to the nearest power of 2 (ceiling) by awgn <awgn@antifork.org> */
static u_char TTL_PREDICTOR (u_char x)
{
  u_char i = x;
  u_char j = 1;
  u_char c = 0;

  do
    {
      c += i & 1;
      j <<= 1;
    } while (i >>= 1);

  return c == 1 ? x : j ? j : 0xff;
}


/* Access the fingerprint hash table to resolve OS name (if not already in and only for SYN or SYN-ACK packets) */
static void resolvsystemname (host_t * h, struct ip * ip, struct tcphdr * tcp, int len)
{
  u_char * opts = (u_char *) tcp + 1;                  /* TCP options (if present) */
  u_char * data = (u_char *) tcp + tcp -> th_off * 4;  /* TCP data (if present)    */

  /* Need to calculate the fingerprint only if the system in currently unknown, there are TCP optionsand the packet is a SYN */
  if (h && ! h -> system && opts != data && tcp -> th_flags & TH_SYN)
    {
      char mss [5] = "_MSS";  /* 4 digit hex field indicating the TCP Option Maximum Segment Size  */
      char ws [3]  = "WS";    /* 2 digit hex field indicating the TCP Option Window Scale          */
      int sack = 0;           /* 1 digit field indicating if the TCP Option SACK permitted is true */
      int nop = 0;            /* 1 digit field indicating if the TCP Options contain a NOP         */
      int ts = 0;             /* 1 digit field indicating if the TCP Timestamp is present          */

      /* TCP options are TLV coded */
      while (opts < data && * opts != TCPOPT_EOL)
	{
	  int type = * opts ++;
	  int len  = type == TCPOPT_EOL || type == TCPOPT_NOP ? 1 : * opts ++;

	  switch (type)
	    {
	    case TCPOPT_EOL: break;
	    case TCPOPT_NOP: nop = 1; break;
	    case TCPOPT_MAXSEG: sprintf (mss, "%04X", * opts & 0xffffffff); break;
	    case TCPOPT_SACK_PERMITTED: sack = 1; break;
	    case TCPOPT_WINDOW: sprintf (ws, "%02X", * opts & 0xffff); break;
	    case TCPOPT_TIMESTAMP: ts = 1; break;

	    default: break;
	    }
	  opts += len - 1;   /* len includes the type too */
	}

      /* Need to build first an unique fingerprint accordingly to the passive OS fingerprint database specification */
      sprintf (h -> fingerprint, "%04X:%s:%02X:%s:%d:%d:%d:%d:%c:%02X",
	       ntohs (tcp -> th_win), mss, TTL_PREDICTOR (ip -> ip_ttl), ws, sack, nop,
	       ntohs (ip -> ip_off) & IP_DF ? 1 : 0, ts, tcp -> th_flags & TH_ACK ? 'A' : 'S', len);

      h -> system = osfingerprintmatch (h -> fingerprint);
    }
}


/* Check if 'ip' belongs to the subnet 'network' with the 'netmask' */
static int islocalhost (uint32_t ip, uint32_t network, uint32_t netmask)
{
  return (ip & netmask) == network;
}


/* Update the TTL distribution by size */
static void ttl_by_size (short ttl, interface_t * interface)
{
  if (ttl <= 32)       interface -> ttl_upto32 ++;
  else if (ttl <= 64)  interface -> ttl_upto64 ++;
  else if (ttl <= 128) interface -> ttl_upto128 ++;
  else if (ttl <= 160) interface -> ttl_upto160 ++;
  else if (ttl <= 192) interface -> ttl_upto192 ++;
  else if (ttl <= 224) interface -> ttl_upto224 ++;
  else                 interface -> ttl_above224 ++;
}


/* Update local vs foreign bytes and packets sent/received distribution */
static void local_vs_foreign (host_t * srchost, host_t * dsthost, int len)
{
  if (srchost && dsthost)
    {
      if (islocalhost (srchost -> ip . s_addr, srchost -> intf -> pcapnetwork, srchost -> intf -> pcapnetmask) &&
	  islocalhost (dsthost -> ip . s_addr, dsthost -> intf -> pcapnetwork, dsthost -> intf -> pcapnetmask))
	srchost -> bytes_sent_local += len,
	  srchost -> pkts_sent_local ++,
	  dsthost -> bytes_recv_local += len,
	  dsthost -> pkts_recv_local ++;
      else if (islocalhost (srchost -> ip . s_addr, srchost -> intf -> pcapnetwork, srchost -> intf -> pcapnetmask) &&
	       ! islocalhost (dsthost -> ip . s_addr, dsthost -> intf -> pcapnetwork, dsthost -> intf -> pcapnetmask))
	srchost -> bytes_sent_foreign += len,
	  srchost -> pkts_sent_foreign ++,
	  dsthost -> bytes_recv_local += len,
	  dsthost -> pkts_recv_local ++;
      else if (! islocalhost (srchost -> ip . s_addr, srchost -> intf -> pcapnetwork, srchost -> intf -> pcapnetmask) &&
	       islocalhost (dsthost -> ip . s_addr, dsthost -> intf -> pcapnetwork, dsthost -> intf -> pcapnetmask))
	srchost -> bytes_sent_local += len,
	  srchost -> pkts_sent_local ++,
	  dsthost -> bytes_recv_foreign += len,
	  dsthost -> pkts_recv_foreign ++;
      else
	srchost -> bytes_sent_foreign += len,
	  srchost -> pkts_sent_foreign ++,
	  dsthost -> bytes_recv_foreign += len,
	  dsthost -> pkts_recv_foreign ++;
    }
}


/* Decoder/counter for the IP Protocol
 *  IP sizes
 *   ip->ip_hl*4        => size of the IP Header only (often 20 bytes)
 *   ntohs (ip->ip_len) => size of the Full IP Packet
 */
void ip (interface_t * intf, header_t * h, u_char * p, host_t * tx, host_t * rx)
{
  /* The IP Protocol */
  struct ip * ip = (struct ip *) p;

  /* Header for the encapsulated protocols (IP, ARP, RARP, ...) */
  header_t header = { p, h -> ts, h -> len - IP_HEADER (ip), h -> caplen - IP_HEADER (ip) };

  char * addr;
  host_t * srchost = NULL;
  host_t * dsthost = NULL;
  protocol_t * protocol;

  /* Update bytes and packets counters */
  intf -> headers_ip += IP_HEADER (ip);
  intf -> bytes_ip += h -> len;
  intf -> pkts_ip ++;

  /* Check for boundaries */
  if (h -> caplen < IP_HEADER (ip))
    return;

  /* Update TTL distribution by size */
  ttl_by_size (ip -> ip_ttl, intf);

  /* Get source IP address */
  addr = inet_ntoa (ip -> ip_src);

  /* Bind the IP address of the transmitting TX host if the source address is on the local subset */
  if (islocalhost (ip -> ip_src . s_addr, intf -> pcapnetwork, intf -> pcapnetmask))
    {
      if (tx && ! tx -> ipaddr)
	tx -> ip = ip -> ip_src,
	  tx -> ipaddr = strdup (addr),
	  resolvhostname (tx);

      srchost = bindtoipnames (intf, addr, tx);    /* The same object is referenced by two keys in hwnames and ipnames */
    }
  else
    /* Add source IP address to the space of known IP names (if not already in) and update bytes and packets counters */
    if ((srchost = addtoipnames (intf, addr)))
      srchost -> bytes_sent += h -> len,
	srchost -> pkts_sent ++;

  /* Update source IP address and hostname (if still missing) */
  if (srchost)
    {
      if (! srchost -> ipaddr)
	srchost -> ip = ip -> ip_src,
	  srchost -> ipaddr = strdup (addr),
	  resolvhostname (srchost);

      /* Update number of IP bytes and packets sent */
      srchost -> bytes_ip_sent += h -> len,
	srchost -> pkts_ip_sent ++;

      /* Update TTL values */
      if (ip -> ip_ttl < 255)
	srchost -> ttl_shortest = MIN (srchost -> ttl_shortest, ip -> ip_ttl),
	  srchost -> ttl_longest = MAX (srchost -> ttl_longest, ip -> ip_ttl);
    }

  /* Lookup for Broadcast destination IP address to avoid its inclusion to the space of known IP names */
  if (ip -> ip_dst . s_addr == intf -> broadcastbin)
    {
      intf -> bytes_ip_broadcast += h -> len,
	intf -> pkts_ip_broadcast ++;
      if (srchost)
	srchost -> bytes_ip_broadcast += h -> len,
	  srchost -> pkts_ip_broadcast ++;
    }
  /* Lookup for destination to all IP addresses to avoid its inclusion to the space of known IP names */
  else if (ip -> ip_dst . s_addr == INADDR_BROADCAST)
    {
      intf -> bytes_ip_all_hosts += h -> len,
	intf -> pkts_ip_all_hosts ++;
      if (srchost)
	srchost -> bytes_ip_all_hosts += h -> len,
	  srchost -> pkts_ip_all_hosts ++;
    }
  /* Lookup for Multicast destination IP address to avoid its inclusion to the space of known IP names
   * Multicast IP addresses range from 224.0.0.0 to 239.255.255.255 */
  else if (IN_MULTICAST (ntohl (ip -> ip_dst . s_addr)))
    {
      intf -> bytes_ip_multicast += h -> len,
	intf -> pkts_ip_multicast ++;
      if (srchost)
	srchost -> bytes_ip_multicast += h -> len,
	  srchost -> pkts_ip_multicast ++;
    }
  else
    {
      /* Get destination IP address */
      addr = inet_ntoa (ip -> ip_dst);

      /* Bind the IP address of the receiving RX host if the destination address is on the local subset */
      if (islocalhost (ip -> ip_dst . s_addr, intf -> pcapnetwork, intf -> pcapnetmask))
	{
	  if (rx && ! rx -> ipaddr)
	    rx -> ip = ip -> ip_dst,
	      rx -> ipaddr = strdup (addr),
	      resolvhostname (rx);

	  dsthost = bindtoipnames (intf, addr, rx);    /* The same object is referenced by two keys in hwnames and ipnames */
	}
      else
	/* Add destination IP address into the space of known IP names (if not already in) and update bytes and packets counters */
	if ((dsthost = addtoipnames (intf, addr)))
	  {
	    dsthost -> bytes_recv += h -> len,
	      dsthost -> pkts_recv ++;

	    /* Update destination IP address and hostname (if still missing) */
	    if (! dsthost -> ipaddr)
	      dsthost -> ip = ip -> ip_dst,
		dsthost -> ipaddr = strdup (addr),
		resolvhostname (dsthost);
	  }

      /* Update number of IP bytes and packets received */
      if (dsthost)
	dsthost -> bytes_ip_recv += h -> len,
	  dsthost -> pkts_ip_recv ++;

      /* Update local vs foreign bytes and packets sent/received distribution */
      local_vs_foreign (srchost, dsthost, h -> len);
    }

  /* Attempt to decode and count packets foreach known protocol id (TCP, UDP, ICMP, ...) */
  if ((protocol = ip_protocol (ip -> ip_p)))
    protocol -> counter (intf, & header, (u_char *) ip + IP_HEADER (ip), srchost, dsthost);
  else
    intf -> bytes_other_ip += h -> len - IP_HEADER (ip),
      intf -> pkts_other_ip ++;
}


/* Decoder/counter for the ARP Protocol */
void arp (interface_t * intf, header_t * h, u_char * p, host_t * srchost, host_t * dsthost)
{
  /* Update bytes and packets counters */
  intf -> bytes_arp += h -> len;
  intf -> pkts_arp ++;

  if (srchost)
    srchost -> bytes_arp_sent += h -> len,
      srchost -> pkts_arp_sent ++;

  if (dsthost)
    dsthost -> bytes_arp_recv += h -> len,
      dsthost -> pkts_arp_recv ++;
}


/* Decoder/counter for the RARP Protocol */
void rarp (interface_t * intf, header_t * h, u_char * p, host_t * srchost, host_t * dsthost)
{
  /* Update bytes and packets counters */
  intf -> bytes_rarp += h -> len;
  intf -> pkts_rarp ++;

  if (srchost)
    srchost -> bytes_rarp_sent += h -> len,
      srchost -> pkts_rarp_sent ++;

  if (dsthost)
    dsthost -> bytes_rarp_recv += h -> len,
      dsthost -> pkts_rarp_recv ++;
}


/* Decoder/counter for the ICMP Protocol */
void icmp (interface_t * intf, header_t * h, u_char * p, host_t * srchost, host_t * dsthost)
{
  /* Update bytes and packets counters */
  intf -> bytes_icmp += h -> len;
  intf -> pkts_icmp ++;

  if (srchost)
    srchost -> bytes_icmp_sent += h -> len,
      srchost -> pkts_icmp_sent ++;

  if (dsthost)
    dsthost -> bytes_icmp_recv += h -> len,
      dsthost -> pkts_icmp_recv ++;
}


/* Decoder/counter for the TCP Protocol
 * TCP sizes
 *
 * tcp->th_off*4 = size of the TCP (Header Only)
 */
void tcp (interface_t * intf, header_t * h, u_char * p, host_t * srchost, host_t * dsthost)
{
  /* The TCP Protocol */
  struct tcphdr * tcp = (struct tcphdr *) p;

  /* Header for the encapsulated protocols (HTTP, FTP, SMTP, ...) */
  header_t header = { p, h -> ts, h -> len - TCP_HEADER (tcp), h -> caplen - TCP_HEADER (tcp) };

#if defined(ROCCO)
  int srcport;
#endif /* ROCCO */
  int dstport;
  protocol_t * protocol;

  /* Update bytes and packets counters */
  intf -> headers_tcp += TCP_HEADER (tcp);
  intf -> bytes_tcp += h -> len;
  intf -> pkts_tcp ++;

  if (srchost)
    srchost -> bytes_tcp_sent += h -> len,
      srchost -> pkts_tcp_sent ++;

  if (dsthost)
    dsthost -> bytes_tcp_recv += h -> len,
      dsthost -> pkts_tcp_recv ++;

  /* Check for boundaries */
  if (h -> caplen < TCP_HEADER (tcp))
    return;

  /* Get source and destination port */
#if defined(ROCCO)
  srcport = ntohs (tcp -> th_sport);
#endif /* ROCCO */
  dstport = ntohs (tcp -> th_dport);

  /* Attempt to resolve OS system name (if not already in) */
  resolvsystemname (srchost, (struct ip *) h -> protocol, tcp, h -> len);
  resolvsystemname (dsthost, (struct ip *) h -> protocol, tcp, h -> len);

  /* Attempt to decode and count packets foreach known destination port (HTTP, FTP, SMTP, ...) */
  if ((protocol = tcp_protocol (dstport)))
    protocol -> counter (intf, & header, (u_char *) tcp + TCP_HEADER (tcp), srchost, dsthost);
  else
    {
      intf -> bytes_other_tcp += h -> len - TCP_HEADER (tcp),
	intf -> pkts_other_tcp ++;

      if (srchost)
	srchost -> bytes_other_tcp_sent += h -> len,
	  srchost -> pkts_other_tcp_sent ++;

      if (dsthost)
	dsthost -> bytes_other_tcp_recv += h -> len,
	  dsthost -> pkts_other_tcp_recv ++;
    }
}


/* Decoder/counter for the UDP Protocol */
void udp (interface_t * intf, header_t * h, u_char * p, host_t * srchost, host_t * dsthost)
{
  /* Update bytes and packets counters */
  intf -> bytes_udp += h -> len;
  intf -> pkts_udp ++;

  if (srchost)
    srchost -> bytes_udp_sent += h -> len,
      srchost -> pkts_udp_sent ++;

  if (dsthost)
    dsthost -> bytes_udp_recv += h -> len,
      dsthost -> pkts_udp_recv ++;
}


/* Decoder/counter for the HTTP Protocol */
void http (interface_t * intf, header_t * h, u_char * p, host_t * srchost, host_t * dsthost)
{
  /* Update bytes and packets counters */
  intf -> bytes_http += h -> len;
  intf -> pkts_http ++;

  if (srchost)
    srchost -> bytes_http_sent += h -> len,
      srchost -> pkts_http_sent ++;

  if (dsthost)
    dsthost -> bytes_http_recv += h -> len,
      dsthost -> pkts_http_recv ++;
}


/* Decoder/counter for the SMTP Protocol */
void smtp (interface_t * intf, header_t * h, u_char * p, host_t * srchost, host_t * dsthost)
{
  /* Update bytes and packets counters */
  intf -> bytes_smtp += h -> len;
  intf -> pkts_smtp ++;

  if (srchost)
    srchost -> bytes_smtp_sent += h -> len,
      srchost -> pkts_smtp_sent ++;

  if (dsthost)
    dsthost -> bytes_smtp_recv += h -> len,
      dsthost -> pkts_smtp_recv ++;
}
