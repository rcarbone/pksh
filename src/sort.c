/*
 * pksh - The Packet Shell
 *
 * R. Carbone (rocco@tecsiel.it)
 * 2003, 2008-2009, 2022
 *
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * General routines to sort the hosts cache
 */


/* Project header */
#include "pksh.h"


/* Sort by Hardware Address */
int sort_by_hwaddr (const void * _a, const void * _b)
{
  if (! (* (host_t **) _a) -> hwaddress && ! (* (host_t **) _b) -> hwaddress)
    return 0;
  else if (! (* (host_t **) _a) -> hwaddress)
    return -1;
  else if (! (* (host_t **) _b) -> hwaddress)
    return 1;
  else
    return strcmp ((* (host_t **) _a) -> hwaddress, (* (host_t **) _b) -> hwaddress);
}


/* Sort by IP address or MAC address (for IP-less hosts) */
int sort_by_ip (const void * _a, const void * _b)
{
  host_t ** a = (host_t **) _a;
  host_t ** b = (host_t **) _b;

  /* IP-less hosts first */
  if (! (* a) -> ipaddr && ! (* b) -> ipaddr)
    return sort_by_hwaddr (_a, _b);
  else if (! (* a) -> ipaddr)
    return -1;
  else if (! (* b) -> ipaddr)
    return 1;
  else
    {
      int a1; int b1; int c1; int d1;
      char ip1 [16];                         /* xxx.xxx.xxx.xxx */

      int a2; int b2; int c2; int d2;
      char ip2 [16];                         /* xxx.xxx.xxx.xxx */

      sscanf ((* a) -> ipaddr, "%d.%d.%d.%d", & a1, & b1, & c1, & d1);
      sprintf (ip1, "%03d%03d%03d%03d", a1, b1, c1, d1);

      sscanf ((* b) -> ipaddr, "%d.%d.%d.%d", & a2, & b2, & c2, & d2);
      sprintf (ip2, "%03d%03d%03d%03d", a2, b2, c2, d2);

      return strcmp (ip1, ip2);
    }
}


/* Sort by hostname/IP address or MAC address (for IP-less hosts) */
int sort_by_hostname (const void * _a, const void * _b)
{
  host_t ** a = (host_t **) _a;
  host_t ** b = (host_t **) _b;

#if defined(FIXME)
  /* Attempt to resolve hostname name first, then sort */
  resolvhostname (* a);
  resolvhostname (* b);
#endif /* FIXME */

  /* IP-less hosts first */
  if (! (* a) -> hostname && ! (* b) -> hostname)
    return sort_by_ip (_a, _b);
  else if (! (* a) -> hostname)
    return -1;
  else if (! (* b) -> hostname)
    return 1;
  else
    {
      int a1; int b1; int c1; int d1; int r1;
      char ip1 [16];                             /* xxx.xxx.xxx.xxx */

      int a2; int b2; int c2; int d2; int r2;
      char ip2 [16];                             /* xxx.xxx.xxx.xxx */

      r1 = sscanf ((* a) -> hostname, "%d.%d.%d.%d", & a1, & b1, & c1, & d1);
      r2 = sscanf ((* b) -> hostname, "%d.%d.%d.%d", & a2, & b2, & c2, & d2);

      if (r1 == 4 && r2 == 4)
	{
	  sprintf (ip1, "%03d%03d%03d%03d", a1, b1, c1, d1);
	  sprintf (ip2, "%03d%03d%03d%03d", a2, b2, c2, d2);
	  return strcmp (ip1, ip2);
	}
      return strcmp ((* a) -> hostname, (* b) -> hostname);
    }
}


/* Sort by vendor name */
int sort_by_vendor (const void * _a, const void * _b)
{
#if defined(FIXME)
  /* Attempt to resolve vendor names first, then sort */
  resolvvendorname (* (host_t **) _a);
  resolvvendorname (* (host_t **) _b);
#endif /* FIXME */

  if (! (* (host_t **) _a) -> vendor && ! (* (host_t **) _b) -> vendor)
    return 0;
  else if (! (* (host_t **) _a) -> vendor)
    return -1;
  else if (! (* (host_t **) _b) -> vendor)
    return 1;
  else
    return strcmp ((* (host_t **) _a) -> vendor, (* (host_t **) _b) -> vendor);
}


/* Sort by OS name */
int sort_by_system (const void * _a, const void * _b)
{
  if (! (* (host_t **) _a) -> system && ! (* (host_t **) _b) -> system)
    return 0;
  else if (! (* (host_t **) _a) -> system)
    return -1;
  else if (! (* (host_t **) _b) -> system)
    return 1;
  else
    return strcmp ((* (host_t **) _a) -> system, (* (host_t **) _b) -> system);
}


/* Sort by domain name */
int sort_by_domain (const void * _a, const void * _b)
{
  return 0;
#if defined(FIXME)
  if (! (* (host_t **) _a) -> domain && ! (* (host_t **) _b) -> domain)
    return 0;
  else if (! (* (host_t **) _a) -> domain)
    return -1;
  else if (! (* (host_t **) _b) -> domain)
    return 1;
  else
    return strcmp ((* (host_t **) _a) -> domain, (* (host_t **) _b) -> domain);
#endif /* FIXME */
}


/* Sort by age */
int sort_by_age (const void * _a, const void * _b)
{
  return usecs (& (* (host_t **) _b) -> last, & (* (host_t **) _b) -> first) -
    usecs (& (* (host_t **) _a) -> last, & (* (host_t **) _a) -> first);
}


/* Sort by date the hosts were first seen */
int sort_by_firstseen (const void * _a, const void * _b)
{
  return usecs (& (* (host_t **) _b) -> first, & (* (host_t **) _a) -> first);
}


/* Sort by date the hosts were last seen */
int sort_by_lastseen (const void * _a, const void * _b)
{
  return usecs (& (* (host_t **) _b) -> last, & (* (host_t **) _a) -> last);
}


/* Sort by # of total bytes sent and received */
int sort_by_bytes_all (const void * _a, const void * _b)
{
  return ((* (host_t **) _b) -> bytes_sent + (* (host_t **) _b) -> bytes_recv) -
    ((* (host_t **) _a) -> bytes_sent + (* (host_t **) _a) -> bytes_recv);
}


/* Sort by # of total Broadcast bytes sent over the interface */
int sort_by_broadcast_bytes (const void * _a, const void * _b)
{
  return (* (host_t **) _b) -> bytes_broadcast - (* (host_t **) _a) -> bytes_broadcast;
}


/* Sort by # of total Multicast bytes sent over the interface */
int sort_by_multicast_bytes (const void * _a, const void * _b)
{
  return (* (host_t **) _b) -> bytes_multicast - (* (host_t **) _a) -> bytes_multicast;
}


/* Sort by # of total IP bytes sent and received */
int sort_by_ip_bytes_all (const void * _a, const void * _b)
{
  return ((* (host_t **) _b) -> bytes_ip_sent + (* (host_t **) _b) -> bytes_ip_recv) -
    ((* (host_t **) _a) -> bytes_ip_sent + (* (host_t **) _a) -> bytes_ip_recv);
}


/* Sort by # of total IP Broadcast bytes sent */
int sort_by_ip_broadcast_bytes (const void * _a, const void * _b)
{
  return (* (host_t **) _b) -> bytes_ip_broadcast - (* (host_t **) _a) -> bytes_ip_broadcast;
}


/* Sort by # of total IP Multicast bytes sent */
int sort_by_ip_multicast_bytes (const void * _a, const void * _b)
{
  return (* (host_t **) _b) -> bytes_ip_multicast - (* (host_t **) _a) -> bytes_ip_multicast;
}


/* Sort by # of total TCP bytes sent and received */
int sort_by_tcp_bytes_all (const void * _a, const void * _b)
{
  return ((* (host_t **) _b) -> bytes_tcp_sent + (* (host_t **) _b) -> bytes_tcp_recv) -
    ((* (host_t **) _a) -> bytes_tcp_sent + (* (host_t **) _a) -> bytes_tcp_recv);
}


/* Sort by # of total UDP bytes sent and received */
int sort_by_udp_bytes_all (const void * _a, const void * _b)
{
  return ((* (host_t **) _b) -> bytes_udp_sent + (* (host_t **) _b) -> bytes_udp_recv) -
    ((* (host_t **) _a) -> bytes_udp_sent + (* (host_t **) _a) -> bytes_udp_recv);
}


/* Sort by # of total ICMP bytes sent and received */
int sort_by_icmp_bytes_all (const void * _a, const void * _b)
{
  return ((* (host_t **) _b) -> bytes_icmp_sent + (* (host_t **) _b) -> bytes_icmp_recv) -
    ((* (host_t **) _a) -> bytes_icmp_sent + (* (host_t **) _a) -> bytes_icmp_recv);
}


/* Sort by # of total Other-IP bytes sent and received */
int sort_by_other_ip_bytes_all (const void * _a, const void * _b)
{
  return ((* (host_t **) _b) -> bytes_other_ip_sent + (* (host_t **) _b) -> bytes_other_ip_recv) -
    ((* (host_t **) _a) -> bytes_other_ip_sent + (* (host_t **) _a) -> bytes_other_ip_recv);
}


/* Sort by # of total bytes sent */
int sort_by_bytes_sent (const void * _a, const void * _b)
{
  return (* (host_t **) _b) -> bytes_sent - (* (host_t **) _a) -> bytes_sent;
}


/* Sort by # of total IP bytes sent */
int sort_by_ip_bytes_sent (const void * _a, const void * _b)
{
  return (* (host_t **) _b) -> bytes_ip_sent - (* (host_t **) _a) -> bytes_ip_sent;
}


/* Sort by # of total TCP bytes sent */
int sort_by_tcp_bytes_sent (const void * _a, const void * _b)
{
  return (* (host_t **) _b) -> bytes_tcp_sent - (* (host_t **) _a) -> bytes_tcp_sent;
}


/* Sort by # of total UDP bytes sent */
int sort_by_udp_bytes_sent (const void * _a, const void * _b)
{
  return (* (host_t **) _b) -> bytes_udp_sent - (* (host_t **) _a) -> bytes_udp_sent;
}


/* Sort by # of total ICMP bytes sent */
int sort_by_icmp_bytes_sent (const void * _a, const void * _b)
{
  return (* (host_t **) _b) -> bytes_icmp_sent - (* (host_t **) _a) -> bytes_icmp_sent;
}


/* Sort by # of total Other-IP bytes sent */
int sort_by_other_ip_bytes_sent (const void * _a, const void * _b)
{
  return (* (host_t **) _b) -> bytes_other_ip_sent - (* (host_t **) _a) -> bytes_other_ip_sent;
}


/* Sort by # of total bytes received */
int sort_by_bytes_recv (const void * _a, const void * _b)
{
  return (* (host_t **) _b) -> bytes_recv - (* (host_t **) _a) -> bytes_recv;
}


/* Sort by # of total IP bytes received */
int sort_by_ip_bytes_recv (const void * _a, const void * _b)
{
  return (* (host_t **) _b) -> bytes_ip_recv - (* (host_t **) _a) -> bytes_ip_recv;
}


/* Sort by # of total TCP bytes received */
int sort_by_tcp_bytes_recv (const void * _a, const void * _b)
{
  return (* (host_t **) _b) -> bytes_tcp_recv - (* (host_t **) _a) -> bytes_tcp_recv;
}


/* Sort by # of total UDP bytes received */
int sort_by_udp_bytes_recv (const void * _a, const void * _b)
{
  return (* (host_t **) _b) -> bytes_udp_recv - (* (host_t **) _a) -> bytes_udp_recv;
}


/* Sort by # of total ICMP bytes received */
int sort_by_icmp_bytes_recv (const void * _a, const void * _b)
{
  return (* (host_t **) _b) -> bytes_icmp_recv - (* (host_t **) _a) -> bytes_icmp_recv;
}


/* Sort by # of total Other-IP bytes received */
int sort_by_other_ip_bytes_recv (const void * _a, const void * _b)
{
  return (* (host_t **) _b) -> bytes_other_ip_recv - (* (host_t **) _a) -> bytes_other_ip_recv;
}


/* Sort by current throughput of bytes sent and received */
int sort_by_current_bytes_all (const void * _a, const void * _b)
{
  return ((* (host_t **) _b) -> bytes_current - (* (host_t **) _a) -> bytes_current);
}

/* Sort by average throughput of bytes sent and received */
int sort_by_average_bytes_all (const void * _a, const void * _b)
{
  return ((* (host_t **) _b) -> bytes_average - (* (host_t **) _a) -> bytes_average);
}

/* Sort by peak throughput of bytes sent and received */
int sort_by_peak_bytes_all (const void * _a, const void * _b)
{
  return ((* (host_t **) _b) -> bytes_peak - (* (host_t **) _a) -> bytes_peak);
}


/* Sort by # of total packets sent and received */
int sort_by_pkts_all (const void * _a, const void * _b)
{
  return ((* (host_t **) _b) -> pkts_sent + (* (host_t **) _b) -> pkts_recv) -
    ((* (host_t **) _a) -> pkts_sent + (* (host_t **) _a) -> pkts_recv);
}


/* Sort by # of total Broadcast packets sent over the interface */
int sort_by_broadcast_pkts (const void * _a, const void * _b)
{
  return (* (host_t **) _b) -> pkts_broadcast - (* (host_t **) _a) -> pkts_broadcast;
}


/* Sort by # of total Multicast packets sent over the interface */
int sort_by_multicast_pkts (const void * _a, const void * _b)
{
  return (* (host_t **) _b) -> pkts_multicast - (* (host_t **) _a) -> pkts_multicast;
}


/* Sort by # of total IP packets sent and received */
int sort_by_ip_pkts_all (const void * _a, const void * _b)
{
  return ((* (host_t **) _b) -> pkts_ip_sent + (* (host_t **) _b) -> pkts_ip_recv) -
    ((* (host_t **) _a) -> pkts_ip_sent + (* (host_t **) _a) -> pkts_ip_recv);
}


/* Sort by # of total IP Broadcast packets sent */
int sort_by_ip_broadcast_pkts (const void * _a, const void * _b)
{
  return (* (host_t **) _b) -> pkts_ip_broadcast - (* (host_t **) _a) -> pkts_ip_broadcast;
}


/* Sort by # of total IP Multicast packets sent */
int sort_by_ip_multicast_pkts (const void * _a, const void * _b)
{
  return (* (host_t **) _b) -> pkts_ip_multicast - (* (host_t **) _a) -> pkts_ip_multicast;
}


/* Sort by # of total TCP packets sent and received */
int sort_by_tcp_pkts_all (const void * _a, const void * _b)
{
  return ((* (host_t **) _b) -> pkts_tcp_sent + (* (host_t **) _b) -> pkts_tcp_recv) -
    ((* (host_t **) _a) -> pkts_tcp_sent + (* (host_t **) _a) -> pkts_tcp_recv);
}


/* Sort by # of total UDP packets sent and received */
int sort_by_udp_pkts_all (const void * _a, const void * _b)
{
  return ((* (host_t **) _b) -> pkts_udp_sent + (* (host_t **) _b) -> pkts_udp_recv) -
    ((* (host_t **) _a) -> pkts_udp_sent + (* (host_t **) _a) -> pkts_udp_recv);
}


/* Sort by # of total ICMP packets sent and received */
int sort_by_icmp_pkts_all (const void * _a, const void * _b)
{
  return ((* (host_t **) _b) -> pkts_icmp_sent + (* (host_t **) _b) -> pkts_icmp_recv) -
    ((* (host_t **) _a) -> pkts_icmp_sent + (* (host_t **) _a) -> pkts_icmp_recv);
}


/* Sort by # of total Other-IP packets sent and received */
int sort_by_other_ip_pkts_all (const void * _a, const void * _b)
{
  return ((* (host_t **) _b) -> pkts_other_ip_sent + (* (host_t **) _b) -> pkts_other_ip_recv) -
    ((* (host_t **) _a) -> pkts_other_ip_sent + (* (host_t **) _a) -> pkts_other_ip_recv);
}


/* Sort by # of total packets sent */
int sort_by_pkts_sent (const void * _a, const void * _b)
{
  return (* (host_t **) _b) -> pkts_sent - (* (host_t **) _a) -> pkts_sent;
}


/* Sort by # of total IP packets sent */
int sort_by_ip_pkts_sent (const void * _a, const void * _b)
{
  return (* (host_t **) _b) -> pkts_ip_sent - (* (host_t **) _a) -> pkts_ip_sent;
}


/* Sort by # of total TCP packets sent */
int sort_by_tcp_pkts_sent (const void * _a, const void * _b)
{
  return (* (host_t **) _b) -> pkts_tcp_sent - (* (host_t **) _a) -> pkts_tcp_sent;
}


/* Sort by # of total UDP packets sent */
int sort_by_udp_pkts_sent (const void * _a, const void * _b)
{
  return (* (host_t **) _b) -> pkts_udp_sent - (* (host_t **) _a) -> pkts_udp_sent;
}


/* Sort by # of total ICMP packets sent */
int sort_by_icmp_pkts_sent (const void * _a, const void * _b)
{
  return (* (host_t **) _b) -> pkts_icmp_sent - (* (host_t **) _a) -> pkts_icmp_sent;
}


/* Sort by # of total Other-IP packets sent */
int sort_by_other_ip_pkts_sent (const void * _a, const void * _b)
{
  return (* (host_t **) _b) -> pkts_other_ip_sent - (* (host_t **) _a) -> pkts_other_ip_sent;
}


/* Sort by # of total packets received */
int sort_by_pkts_recv (const void * _a, const void * _b)
{
  return (* (host_t **) _b) -> pkts_recv - (* (host_t **) _a) -> pkts_recv;
}


/* Sort by # of total IP packets received */
int sort_by_ip_pkts_recv (const void * _a, const void * _b)
{
  return (* (host_t **) _b) -> pkts_ip_recv - (* (host_t **) _a) -> pkts_ip_recv;
}


/* Sort by # of total TCP packets received */
int sort_by_tcp_pkts_recv (const void * _a, const void * _b)
{
  return (* (host_t **) _b) -> pkts_tcp_recv - (* (host_t **) _a) -> pkts_tcp_recv;
}


/* Sort by # of total UDP packets received */
int sort_by_udp_pkts_recv (const void * _a, const void * _b)
{
  return (* (host_t **) _b) -> pkts_udp_recv - (* (host_t **) _a) -> pkts_udp_recv;
}


/* Sort by # of total ICMP packets received */
int sort_by_icmp_pkts_recv (const void * _a, const void * _b)
{
  return (* (host_t **) _b) -> pkts_icmp_recv - (* (host_t **) _a) -> pkts_icmp_recv;
}


/* Sort by # of total Other-IP packets received */
int sort_by_other_ip_pkts_recv (const void * _a, const void * _b)
{
  return (* (host_t **) _b) -> pkts_other_ip_recv - (* (host_t **) _a) -> pkts_other_ip_recv;
}


/* Sort by current throughput of packets sent and received */
int sort_by_current_pkts_all (const void * _a, const void * _b)
{
  return ((* (host_t **) _b) -> pkts_current - (* (host_t **) _a) -> pkts_current);
}


/* Sort by average throughput of packets sent and received */
int sort_by_average_pkts_all (const void * _a, const void * _b)
{
  return ((* (host_t **) _b) -> pkts_average - (* (host_t **) _a) -> pkts_average);
}


/* Sort by peak throughput of packets sent and received */
int sort_by_peak_pkts_all (const void * _a, const void * _b)
{
  return ((* (host_t **) _b) -> pkts_peak - (* (host_t **) _a) -> pkts_peak);
}
