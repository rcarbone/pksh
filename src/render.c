/*
 * pksh - The Packet Shell
 *
 * R. Carbone (rocco@tecsiel.it)
 * 2008-2009, 2022
 *
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Rendering routines to have a well formatted output for bytes, packets, hosts and protocols
 */


/* System headers */
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>

/* Project header */
#include "pksh.h"


/* Constants */
#define BUFFERS           12
#define BUFFERSIZE        32

#define FIXED_BYTES_LEN    9
#define FIXED_PKTS_LEN     9
#define FIXED_LEN_NAME     6
#define FIXED_LEN_DLT      6
#define FIXED_LEN_MAC     17     /* xx:xx:xx:xx:xx:xx for Ethernet */
#define FIXED_LEN_IP      15     /* xxx.xxx.xxx.xxx */
#define FIXED_LEN_VENDOR  27
#define FIXED_LEN_OS_NAME 15
#define FIXED_LEN_SEEN    19


/* Format a centered string */
static char * center (char * str, char * s, int max)
{
  int x;  /* initial blanks */
  int y;  /* the string itself */
  int z;  /* final blanks */
  void * a;
  void * b;
  void * c;

  if (! s)
    {
      sprintf (str, "%*c", max, ' ');
      return str;
    }

  y = strlen (s);
  x = (max - y) / 2;
  z = max - x - y;

  a = calloc (1, max + 1);
  b = calloc (1, max + 1);
  c = calloc (1, max + 1);

  if (x > 0)
    sprintf (a, "%*c", x, ' ');         /* header */
  if (y < max)
    sprintf (b, "%-*.*s", y, y, s);     /* string */
  else
    sprintf (b, "%-*.*s", max, max, s);
  if (z > 0)
    sprintf (c, "%*c", z, ' ');         /* footer */

  sprintf (str, "%s%s%s", (char *) a, (char *) b, (char *) c);

  free (a); free (b); free (c);

  return str;
}


/* Format a centered number */
static char * ncenter (char * str, counter_t n, int max)
{
  static char buffer [16];
  sprintf (buffer, "%lu", (unsigned long) n);
  return center (str, buffer, max);
}


/* Well formatted bytes counter */
char * fmtbytes (counter_t bytes)
{
  static char buffer [BUFFERS] [BUFFERSIZE];
  static short which = -1;

  which = (which + 1) % BUFFERS;   /* round-robin in the array of local buffers */

  if (bytes < 1024)
    sprintf (buffer [which], "%lu Bytes", (unsigned long) bytes);
  else if (bytes < 1048576)
    sprintf (buffer [which], "%5.1f Kb", (float) bytes / 1024);
  else
    {
      float mega = bytes / 1048576;
      if (mega < 1024)
	sprintf (buffer [which], "%5.1f MB", mega);
      else
	{
	  mega /= 1024;
	  if (mega < 1024)
	    sprintf (buffer [which], "%5.1f GB", mega);
	  else
	    sprintf (buffer [which], "%.1f TB", mega / 1024);
	}
    }
  return buffer [which];
}


/* Well formatted bytes of fixed length for better rendering in tables */
static char * nfmtbytes (counter_t bytes)
{
  static char buffer [BUFFERSIZE];

  if (bytes < 1024)
    return ncenter (buffer, bytes, FIXED_BYTES_LEN);
  else if (bytes < 1048576)
    sprintf (buffer, "%6.1f Kb", (float) bytes / 1024);
  else
    {
      float mega = (float) (bytes / 1048576);
      if (mega < 1024)
	sprintf (buffer, "%6.1f MB", mega);
      else
	{
	  mega /= 1024;
	  if (mega < 1024)
	    sprintf (buffer, "%6.1f GB", mega);
	  else
	    sprintf (buffer, "%6.1f TB", (float) mega / 1024);
	}
    }
  return buffer;
}


#if defined(FIXME)
/* Centered bytes (exactly) */
static char * efmtbytes (counter_t bytes)
{
  static char buffer [BUFFERSIZE];
  return ncenter (buffer, bytes, FIXED_BYTES_LEN);
}
#endif /* FIXME */

/* Well formatted Packets */
char * fmtpkts (counter_t pkts)
{
  static char buffer [BUFFERS] [BUFFERSIZE];
  static short which = -1;

  which = (which + 1) % BUFFERS;   /* round-robin in the array of local buffers */

  if (pkts < 1000)
    sprintf (buffer [which], "%lu", (unsigned long) pkts);
  else if (pkts < 1000000)
    sprintf (buffer [which], "%lu,%03lu", (unsigned long) pkts / 1000, (unsigned long) pkts % 1000);
  else
    sprintf (buffer [which], "%lu,%03lu,%03lu",
	     (unsigned long) (pkts / 1000000),
	     (unsigned long) (pkts - (pkts / 1000000) * 1000000) / 1000,
	     (unsigned long) pkts % 1000);

  return buffer [which];
}


static char * nfmtpkts (counter_t pkts)
{
  static char buffer [BUFFERSIZE];
  return ncenter (buffer, pkts, FIXED_PKTS_LEN);
}


/* Well formatted Throughput */
char * throughputfmt (float bytes)
{
  static char buffer [BUFFERS] [BUFFERSIZE];
  static short which = -1;

  float bits;

  which = (which + 1) % BUFFERS;   /* round-robin in the array of local buffers */

  if (bytes < 0)
    bytes = 0; /* Sanity check */
  bits = bytes * 8;

  if (bits < 100)
    bits = 0; /* Avoid very small decimal values */

  if (bits < 1024)
    sprintf (buffer [which], "%.1f ", bits);
  else if (bits < 1048576)
    sprintf (buffer [which], "%.1f Kbps", bits / 1024);
  else
    sprintf (buffer [which], "%.1f Mbps", bits / 1048576);

  return buffer [which];
}


/* Well formatted Percentage */
char * percentage (counter_t partial, counter_t total)
{
#define ITEMS 10
  static char buffer [ITEMS] [64];
  static short k = -1;

#define DECIMALS 2
  float percent;

  k = (k + 1) % ITEMS;

  if (partial && total)
    {
      percent = (float) partial * 100 / (float) total;

      if (partial == total)
	sprintf (buffer [k], " (%3d%%) ", (int) percent);
      else if (percent < 10)
	sprintf (buffer [k], " (%4.*f%%)", DECIMALS, percent);  /* d.dd% */
      else
	sprintf (buffer [k], "(%4.*f%%)", DECIMALS, percent);   /* d.dd% */
    }
  else
    sprintf (buffer [k], "        ");    /* 8 blanks */

  return buffer [k];
}


/* True only if 'h' has a hardware address */
int hostlocal (host_t * h)
{
  return h -> hwaddress ? 1 : 0;
}


/* True only if 'h' does not have an IP address */
int hostipless (host_t * h)
{
  return h -> ipaddr ? 0 : 1;
}


/* True only if 'h' does not have a hostname */
int hostunresolved (host_t * h)
{
  return h -> hostname ? 0 : 1;
}


/* Return the total # of bytes sent/received over a data-link interface */
static counter_t bytes_total (host_t * h)
{
  return h -> bytes_ip_sent + h -> bytes_ip_recv +
    h -> bytes_arp_sent + h -> bytes_arp_recv +
    h -> bytes_rarp_sent + h -> bytes_rarp_recv +
    h -> bytes_non_ip_sent + h -> bytes_non_ip_recv;
}


/* Return the total # of packets sent/received over a data-link interface */
static counter_t pkts_total (host_t * h)
{
  return h -> pkts_ip_sent + h -> pkts_ip_recv +
    h -> pkts_arp_sent + h -> pkts_arp_recv +
    h -> pkts_rarp_sent + h -> pkts_rarp_recv +
    h -> pkts_non_ip_sent + h -> pkts_non_ip_recv;
}


/* Return the total # of IP bytes sent/received over a data-link interface */
static counter_t bytes_ip_total (host_t * h)
{
  return h -> bytes_tcp_sent + h -> bytes_tcp_recv +
    h -> bytes_udp_sent + h -> bytes_udp_recv +
    h -> bytes_icmp_sent + h -> bytes_icmp_recv +
    h -> bytes_other_ip_sent + h -> bytes_other_ip_recv;
}


/* Return the total # of IP packets sent/received over a data-link interface */
static counter_t pkts_ip_total (host_t * h)
{
  return h -> pkts_tcp_sent + h -> pkts_tcp_recv +
    h -> pkts_udp_sent + h -> pkts_udp_recv +
    h -> pkts_icmp_sent + h -> pkts_icmp_recv +
    h -> pkts_other_ip_sent + h -> pkts_other_ip_recv;
}


/* Return the total # of TCP bytes sent/received over a data-link interface */
static counter_t bytes_tcp_total (host_t * h)
{
  return h -> bytes_http_sent + h -> bytes_http_recv +
    h -> bytes_smtp_sent + h -> bytes_smtp_recv +
    h -> bytes_other_tcp_sent + h -> bytes_other_tcp_recv;
}


/* Return the total # of TCP packets sent/received over a data-link interface */
static counter_t pkts_tcp_total (host_t * h)
{
  return h -> pkts_http_sent + h -> pkts_http_recv +
    h -> pkts_smtp_sent + h -> pkts_smtp_recv +
    h -> pkts_other_tcp_sent + h -> pkts_other_tcp_recv;
}


static void interface_printf (host_t * h)
{
  printf ("%-*.*s", FIXED_LEN_NAME, FIXED_LEN_NAME, h -> intf -> name);
}


static void datalink_printf (host_t * h)
{
  printf ("%-*.*s", FIXED_LEN_DLT, FIXED_LEN_DLT, pcap_datalink_val_to_name (h -> intf -> datalink));
}


static void mac_printf (host_t * h)
{
  printf ("%-*.*s", FIXED_LEN_MAC, FIXED_LEN_MAC, h -> hwaddress ? h -> hwaddress : " ");
}


#if defined(FIXME)
static void well_mac_printf (host_t * h)
{
  /* Attempt to resolve vendor name first, then print */
  resolvvendorname (h);

  if (h -> vendor)
    {
      char x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12;
      char * a;

      /* Strip long names */                   /* FIXME: better in vendor.c IMO */
      if ((a = strchr (h -> vendor, ' ')))
	* a = '\0';

      sscanf (h -> hwaddress, "%c%c:%c%c:%c%c:%c%c:%c%c:%c%c", & x1, & x2, & x3, & x4, & x5, & x6, & x7, & x8, & x9, & x10, & x11, & x12);
      printf ("%s:%c%c:%c%c:%c%c", h -> vendor, x7, x8, x9, x10, x11, x12);
    }
  else
    printf ("%s", h -> hwaddress);
}
#endif /* FIXME */

static void ip_printf (host_t * h)
{
  if (hostipless (h))
    printf ("%-*.*s", FIXED_LEN_IP, FIXED_LEN_IP, " ");
  else
    printf ("%-*.*s", FIXED_LEN_IP, FIXED_LEN_IP, h -> ipaddr);
}


static void hostname_printf (host_t * h, char * label)
{
  int width = 0;

#if defined(FIXME)
  /* Attempt to resolve hostname name first, then print */
  resolvhostname (h);
#endif /* FIXME */

  if (! h -> hostname)
    width = label ? atoi (label) : strlen ("_unresolved_"),   /* The DNS is still getting the entry name */
      printf ("%-*.*s", width, width, "_unresolved_");
  else if (hostipless (h))                                    /* Null-IP */
    printf ("%-*.*s", FIXED_LEN_IP, FIXED_LEN_IP, " ");
  else if (h -> hostname)
    width = label ? atoi (label) : strlen (h -> hostname),
      printf ("%-*.*s", width, width, h -> hostname);
  else
    width = label ? atoi (label) : 0,
      printf ("%-*.*s", width, width, label ? label : " ");
}


static void numeric_id_printf (host_t * h, char * label)
{
  int width = 0;

  if (hostipless (h))
    width = label ? atoi (label) : FIXED_LEN_MAC,
      printf ("%-*.*s", width, width, h -> hwaddress);
  else if (h -> ipaddr)
    width = label ? atoi (label) : strlen (h -> ipaddr),
      printf ("%-*.*s", width, width, h -> ipaddr);
  else
    width = label ? atoi (label) : 0,
      printf ("%-*.*s", width, width, label ? label : " ");
}


void unique_id_printf (host_t * h, char * label)
{
  int width = 0;

#if defined(FIXME)
  /* Attempt to resolve hostname name first, then print */
  resolvhostname (h);
#endif /* FIXME */

  if (hostipless (h))
    width = label ? atoi (label) : FIXED_LEN_MAC,
      printf ("%-*.*s", width, width, h -> hwaddress);
  else if (h -> hostname)
    width = label ? atoi (label) : strlen (h -> hostname),
      printf ("%-*.*s", width, width, h -> hostname);
  else if (h -> ipaddr)
    width = label ? atoi (label) : strlen (h -> ipaddr),
      printf ("%-*.*s", width, width, h -> ipaddr);
  else
    width = label ? atoi (label) : 0,
      printf ("%-*.*s", width, width, label ? label : " ");
}


static void ipless_id_printf (host_t * h, char * label)
{
  int width = 0;

#if defined(FIXME)
  /* Attempt to resolve hostname name first, then print */
  resolvhostname (h);
#endif /* FIXME */

  if (hostipless (h))
    width = label ? atoi (label) : FIXED_LEN_MAC,
      printf ("%-*.*s", width, width, " ");
  else if (h -> hostname)
    width = label ? atoi (label) : strlen (h -> hostname),
      printf ("%-*.*s", width, width, h -> hostname);
  else if (h -> ipaddr)
    width = label ? atoi (label) : strlen (h -> ipaddr),
      printf ("%-*.*s", width, width, h -> ipaddr);
  else
    width = label ? atoi (label) : 0,
      printf ("%-*.*s", width, width, label ? label : " ");
}


static void vendor_printf (host_t * h, char * label)
{
  int width = 0;

#if defined(FIXME)
  /* Attempt to resolve vendor name first, then print */
  resolvvendorname (h);
#endif /* FIXME */

  if (h -> vendor)
    width = label ? atoi (label) : strlen (h -> vendor),
      printf ("%-*.*s", width, width, h -> vendor);
  else
    printf ("%-*.*s", FIXED_LEN_VENDOR, FIXED_LEN_VENDOR, " ");
}


#if defined(FIXME)
static void well_vendor_printf (host_t * h)
{
  /* Attempt to resolve vendor name first, then print */
  resolvvendorname (h);

  if (h -> vendor)
    {
      char * a;
      char x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12;

      if ((a = strchr (h -> vendor, ' ')))
	* a = '\0';

      sscanf (h -> hwaddress, "%c%c:%c%c:%c%c:%c%c:%c%c:%c%c", & x1, & x2, & x3, & x4, & x5, & x6, & x7, & x8, & x9, & x10, & x11, & x12);
      printf (" [%s]", h -> vendor);
    }
  else
    printf ("%-*.*s", FIXED_LEN_VENDOR, FIXED_LEN_VENDOR, " ");
}
#endif /* FIXME */


static void os_system_printf (host_t * h, char * label)
{
  int width = 0;

  if (h -> system)
    width = label ? atoi (label) : strlen (h -> system),
      printf ("%-*.*s", width, width, h -> system);
  else
    printf ("%-*.*s", FIXED_LEN_OS_NAME, FIXED_LEN_OS_NAME, " ");
}


static void domain_printf (host_t * h, char * label)
{
#if defined(FIXME)
  int width = 0;

  width = label ? atoi (label) : h -> domain ? strlen (h -> domain) : 0;
  printf ("%-*.*s", width, width, h -> domain ? h -> domain : " ");
#endif /* FIXME */
}


void firstseen_printf (host_t * h)
{
  printf ("%-*.*s", FIXED_LEN_SEEN, FIXED_LEN_SEEN, ctime (& h -> first . tv_sec));
}


void lastseen_printf (host_t * h)
{
  printf ("%-*.*s", FIXED_LEN_SEEN, FIXED_LEN_SEEN, ctime (& h -> last . tv_sec));
}


/* Age uptime-like format [ 0 day(s)  1:28:44] */
static void age_last_printf (host_t * h)
{
  printf ("%-*.*s - ", FIXED_LEN_SEEN, FIXED_LEN_SEEN, ctime (& h -> first . tv_sec));
  printf ("%-8.8s  ", ctime (& h -> last . tv_sec) + 11);
  printf ("(%02d:%02d:%02d)",
	  tvhours (& h -> last, & h -> first), tvmins (& h -> last, & h -> first), tvsecs (& h -> last, & h -> first));
}


/* Age last-like format [Tue Apr 22 18:19 - 09:01  (15:42)] */
void age_uptime_printf (host_t * h)
{
  printf ("%3d day(s) %02d:%02d:%02d",
	  tvdays (& h -> last, & h -> first), tvhours (& h -> last, & h -> first), tvmins (& h -> last, & h -> first), tvsecs (& h -> last, & h -> first));
}


/* Idle uptime format */
void idle_uptime_printf (host_t * h)
{
  struct timeval now;
  gettimeofday (& now, NULL);

  printf ("%3d day(s) %02d:%02d:%02d",
	  tvdays (& now, & h -> last), tvhours (& now, & h -> last), tvmins (& now, & h -> last), tvsecs (& now, & h -> first));
}


/*
 * Find the longest host identifer for better output rendering
 *
 * 1. the MAC address is the unique identifier for IP-less hosts
 * 2. the symbolic host name is used if there is one
 * 3. otherwise choose one between the numeric IP address or the MAC address
 */
int hostlongest (host_t * argv [], int numeric)
{
  int longest = strlen ("Host Id");  /* default longest hostname */
  host_t ** h = argv;

  while (h && * h)
    {
      int now = 0;

#if defined(FIXME)
      /* Attempt to resolve hostname name first, then calculate */
      resolvhostname (* h);
#endif /* FIXME */

      if (hostipless (* h) && (* h) -> hwaddress)
	now = strlen ((* h) -> hwaddress);
      else if (! numeric && (* h) -> hostname)
	now = strlen ((* h) -> hostname);
      else if (! hostipless (* h) && (* h) -> ipaddr)
	now = strlen ((* h) -> ipaddr);
      else
	now = (* h) -> hwaddress ? strlen ((* h) -> hwaddress) : 0;
      longest = MAX (longest, now);
      h ++;
    }
  return longest;
}


/* Total bytes (sent + received) all protocols */
static void total_bytes_all_printf (host_t * h)            { printf ("%s", nfmtbytes (h -> bytes_sent + h -> bytes_recv)); }
static void total_bytes_unicast_printf (host_t * h)        { printf ("%s", nfmtbytes (h -> bytes_sent + h -> bytes_recv - h -> bytes_broadcast - h -> bytes_multicast)); }
static void total_bytes_broadcast_printf (host_t * h)      { printf ("%s", nfmtbytes (h -> bytes_broadcast)); }
static void total_bytes_multicast_printf (host_t * h)      { printf ("%s", nfmtbytes (h -> bytes_multicast)); }
static void total_bytes_ip_all_printf (host_t * h)         { printf ("%s", nfmtbytes (h -> bytes_ip_sent + h -> bytes_ip_recv)); }
static void total_bytes_ip_broadcast_printf (host_t * h)   { printf ("%s", nfmtbytes (h -> bytes_ip_broadcast)); }
static void total_bytes_ip_multicast_printf (host_t * h)   { printf ("%s", nfmtbytes (h -> bytes_ip_multicast)); }
#if defined(FIXME)
static void total_bytes_ip_all_hosts_printf (host_t * h)   { printf ("%s", nfmtbytes (h -> bytes_ip_all_hosts)); }
#endif /* FIXME */
static void total_bytes_arp_all_printf (host_t * h)        { printf ("%s", nfmtbytes (h -> bytes_arp_sent + h -> bytes_arp_recv)); }
static void total_bytes_rarp_all_printf (host_t * h)       { printf ("%s", nfmtbytes (h -> bytes_rarp_sent + h -> bytes_rarp_recv)); }
static void total_bytes_non_ip_all_printf (host_t * h)     { printf ("%s", nfmtbytes (h -> bytes_non_ip_sent + h -> bytes_non_ip_recv)); }
static void total_bytes_tcp_all_printf (host_t * h)        { printf ("%s", nfmtbytes (h -> bytes_tcp_sent + h -> bytes_tcp_recv)); }
static void total_bytes_udp_all_printf (host_t * h)        { printf ("%s", nfmtbytes (h -> bytes_udp_sent + h -> bytes_udp_recv)); }
static void total_bytes_icmp_all_printf (host_t * h)       { printf ("%s", nfmtbytes (h -> bytes_icmp_sent + h -> bytes_icmp_recv)); }
static void total_bytes_other_ip_all_printf (host_t * h)   { printf ("%s", nfmtbytes (h -> bytes_other_ip_sent + h -> bytes_other_ip_recv)); }
static void total_bytes_http_all_printf (host_t * h)       { printf ("%s", nfmtbytes (h -> bytes_http_sent + h -> bytes_http_recv)); }
static void total_bytes_smtp_all_printf (host_t * h)       { printf ("%s", nfmtbytes (h -> bytes_smtp_sent + h -> bytes_smtp_recv)); }
static void total_bytes_other_tcp_all_printf (host_t * h)  { printf ("%s", nfmtbytes (h -> bytes_other_tcp_sent + h -> bytes_other_tcp_recv)); }

/* Total bytes sent all protocols */
static void total_bytes_sent_printf (host_t * h)           { printf ("%s", nfmtbytes (h -> bytes_sent)); }
static void total_bytes_unicast_sent_printf (host_t * h)   { printf ("%s", nfmtbytes (h -> bytes_sent - h -> bytes_broadcast - h -> bytes_multicast)); }
static void total_bytes_ip_sent_printf (host_t * h)        { printf ("%s", nfmtbytes (h -> bytes_ip_sent)); }
static void total_bytes_arp_sent_printf (host_t * h)       { printf ("%s", nfmtbytes (h -> bytes_arp_sent)); }
static void total_bytes_rarp_sent_printf (host_t * h)      { printf ("%s", nfmtbytes (h -> bytes_rarp_sent)); }
static void total_bytes_non_ip_sent_printf (host_t * h)    { printf ("%s", nfmtbytes (h -> bytes_non_ip_sent)); }
static void total_bytes_tcp_sent_printf (host_t * h)       { printf ("%s", nfmtbytes (h -> bytes_tcp_sent)); }
static void total_bytes_udp_sent_printf (host_t * h)       { printf ("%s", nfmtbytes (h -> bytes_udp_sent)); }
static void total_bytes_icmp_sent_printf (host_t * h)      { printf ("%s", nfmtbytes (h -> bytes_icmp_sent)); }
static void total_bytes_other_ip_sent_printf (host_t * h)  { printf ("%s", nfmtbytes (h -> bytes_other_ip_sent)); }
static void total_bytes_http_sent_printf (host_t * h)      { printf ("%s", nfmtbytes (h -> bytes_http_sent)); }
static void total_bytes_smtp_sent_printf (host_t * h)      { printf ("%s", nfmtbytes (h -> bytes_smtp_sent)); }
static void total_bytes_other_tcp_sent_printf (host_t * h) { printf ("%s", nfmtbytes (h -> bytes_other_tcp_sent)); }

/* Total bytes received all protocols */
static void total_bytes_recv_printf (host_t * h)           { printf ("%s", nfmtbytes (h -> bytes_recv)); }
static void total_bytes_unicast_recv_printf (host_t * h)   { printf ("%s", nfmtbytes (h -> bytes_recv)); }
static void total_bytes_ip_recv_printf (host_t * h)        { printf ("%s", nfmtbytes (h -> bytes_ip_recv)); }
static void total_bytes_arp_recv_printf (host_t * h)       { printf ("%s", nfmtbytes (h -> bytes_arp_recv)); }
static void total_bytes_rarp_recv_printf (host_t * h)      { printf ("%s", nfmtbytes (h -> bytes_rarp_recv)); }
static void total_bytes_non_ip_recv_printf (host_t * h)    { printf ("%s", nfmtbytes (h -> bytes_non_ip_recv)); }
static void total_bytes_tcp_recv_printf (host_t * h)       { printf ("%s", nfmtbytes (h -> bytes_tcp_recv)); }
static void total_bytes_udp_recv_printf (host_t * h)       { printf ("%s", nfmtbytes (h -> bytes_udp_recv)); }
static void total_bytes_icmp_recv_printf (host_t * h)      { printf ("%s", nfmtbytes (h -> bytes_icmp_recv)); }
static void total_bytes_other_ip_recv_printf (host_t * h)  { printf ("%s", nfmtbytes (h -> bytes_other_ip_recv)); }
static void total_bytes_http_recv_printf (host_t * h)      { printf ("%s", nfmtbytes (h -> bytes_http_recv)); }
static void total_bytes_smtp_recv_printf (host_t * h)      { printf ("%s", nfmtbytes (h -> bytes_smtp_recv)); }
static void total_bytes_other_tcp_recv_printf (host_t * h) { printf ("%s", nfmtbytes (h -> bytes_other_tcp_recv)); }

/* Total packets (sent + received) all protocols */
static void total_pkts_all_printf (host_t * h)             { printf ("%s", nfmtpkts (h -> pkts_sent + h -> pkts_recv)); }
static void total_pkts_unicast_printf (host_t * h)         { printf ("%s", nfmtpkts (h -> pkts_sent + h -> pkts_recv - h -> pkts_broadcast - h -> pkts_multicast)); }
static void total_pkts_broadcast_printf (host_t * h)       { printf ("%s", nfmtpkts (h -> pkts_broadcast)); }
static void total_pkts_multicast_printf (host_t * h)       { printf ("%s", nfmtpkts (h -> pkts_multicast)); }
static void total_pkts_ip_all_printf (host_t * h)          { printf ("%s", nfmtpkts (h -> pkts_ip_sent + h -> pkts_ip_recv)); }
static void total_pkts_ip_broadcast_printf (host_t * h)    { printf ("%s", nfmtpkts (h -> pkts_ip_broadcast)); }
static void total_pkts_ip_multicast_printf (host_t * h)    { printf ("%s", nfmtpkts (h -> pkts_ip_multicast)); }
#if defined(FIXME)
static void total_pkts_ip_all_hosts_printf (host_t * h)    { printf ("%s", nfmtpkts (h -> pkts_ip_all_hosts)); }
#endif /* FIXME */
static void total_pkts_arp_all_printf (host_t * h)         { printf ("%s", nfmtpkts (h -> pkts_arp_sent + h -> pkts_arp_recv)); }
static void total_pkts_rarp_all_printf (host_t * h)        { printf ("%s", nfmtpkts (h -> pkts_rarp_sent + h -> pkts_rarp_recv)); }
static void total_pkts_non_ip_all_printf (host_t * h)      { printf ("%s", nfmtpkts (h -> pkts_non_ip_sent + h -> pkts_non_ip_recv)); }
static void total_pkts_tcp_all_printf (host_t * h)         { printf ("%s", nfmtpkts (h -> pkts_tcp_sent + h -> pkts_tcp_recv)); }
static void total_pkts_udp_all_printf (host_t * h)         { printf ("%s", nfmtpkts (h -> pkts_udp_sent + h -> pkts_udp_recv)); }
static void total_pkts_icmp_all_printf (host_t * h)        { printf ("%s", nfmtpkts (h -> pkts_icmp_sent + h -> pkts_icmp_recv)); }
static void total_pkts_other_ip_all_printf (host_t * h)    { printf ("%s", nfmtpkts (h -> pkts_other_ip_sent + h -> pkts_other_ip_recv)); }
static void total_pkts_http_all_printf (host_t * h)        { printf ("%s", nfmtpkts (h -> pkts_http_sent + h -> pkts_http_recv)); }
static void total_pkts_smtp_all_printf (host_t * h)        { printf ("%s", nfmtpkts (h -> pkts_smtp_sent + h -> pkts_smtp_recv)); }
static void total_pkts_other_tcp_all_printf (host_t * h)   { printf ("%s", nfmtpkts (h -> pkts_other_tcp_sent + h -> pkts_other_tcp_recv)); }

/* Total packets sent all protocols */
static void total_pkts_sent_printf (host_t * h)            { printf ("%s", nfmtpkts (h -> pkts_sent)); }
static void total_pkts_unicast_sent_printf (host_t * h)    { printf ("%s", nfmtpkts (h -> pkts_sent - h -> pkts_broadcast - h -> pkts_multicast)); }
static void total_pkts_ip_sent_printf (host_t * h)         { printf ("%s", nfmtpkts (h -> pkts_ip_sent)); }
static void total_pkts_arp_sent_printf (host_t * h)        { printf ("%s", nfmtpkts (h -> pkts_arp_sent)); }
static void total_pkts_rarp_sent_printf (host_t * h)       { printf ("%s", nfmtpkts (h -> pkts_rarp_sent)); }
static void total_pkts_non_ip_sent_printf (host_t * h)     { printf ("%s", nfmtpkts (h -> pkts_non_ip_sent)); }
static void total_pkts_tcp_sent_printf (host_t * h)        { printf ("%s", nfmtpkts (h -> pkts_tcp_sent)); }
static void total_pkts_udp_sent_printf (host_t * h)        { printf ("%s", nfmtpkts (h -> pkts_udp_sent)); }
static void total_pkts_icmp_sent_printf (host_t * h)       { printf ("%s", nfmtpkts (h -> pkts_icmp_sent)); }
static void total_pkts_other_ip_sent_printf (host_t * h)   { printf ("%s", nfmtpkts (h -> pkts_other_ip_sent)); }
static void total_pkts_http_sent_printf (host_t * h)       { printf ("%s", nfmtpkts (h -> pkts_http_sent)); }
static void total_pkts_smtp_sent_printf (host_t * h)       { printf ("%s", nfmtpkts (h -> pkts_smtp_sent)); }
static void total_pkts_other_tcp_sent_printf (host_t * h)  { printf ("%s", nfmtpkts (h -> pkts_other_tcp_sent)); }

/* Total packets received all protocols */
static void total_pkts_recv_printf (host_t * h)            { printf ("%s", nfmtpkts (h -> pkts_recv)); }
static void total_pkts_unicast_recv_printf (host_t * h)    { printf ("%s", nfmtpkts (h -> pkts_recv)); }
static void total_pkts_ip_recv_printf (host_t * h)         { printf ("%s", nfmtpkts (h -> pkts_ip_recv)); }
static void total_pkts_arp_recv_printf (host_t * h)        { printf ("%s", nfmtpkts (h -> pkts_arp_recv)); }
static void total_pkts_rarp_recv_printf (host_t * h)       { printf ("%s", nfmtpkts (h -> pkts_rarp_recv)); }
static void total_pkts_non_ip_recv_printf (host_t * h)     { printf ("%s", nfmtpkts (h -> pkts_non_ip_recv)); }
static void total_pkts_tcp_recv_printf (host_t * h)        { printf ("%s", nfmtpkts (h -> pkts_tcp_recv)); }
static void total_pkts_udp_recv_printf (host_t * h)        { printf ("%s", nfmtpkts (h -> pkts_udp_recv)); }
static void total_pkts_icmp_recv_printf (host_t * h)       { printf ("%s", nfmtpkts (h -> pkts_icmp_recv)); }
static void total_pkts_other_ip_recv_printf (host_t * h)   { printf ("%s", nfmtpkts (h -> pkts_other_ip_recv)); }
static void total_pkts_http_recv_printf (host_t * h)       { printf ("%s", nfmtpkts (h -> pkts_http_recv)); }
static void total_pkts_smtp_recv_printf (host_t * h)       { printf ("%s", nfmtpkts (h -> pkts_smtp_recv)); }
static void total_pkts_other_tcp_recv_printf (host_t * h)  { printf ("%s", nfmtpkts (h -> pkts_other_tcp_recv)); }


/* Print network usage in terms of bytes */
void bytes_distribution (host_t * h)
{
  printf ("\n");
  printf ("Bytes               Total     %%         Sent    %%         Rcvd    %%\n");

  printf ("  Processed    : ");
  total_bytes_all_printf (h);  printf (" %s", percentage (h -> bytes_sent + h -> bytes_recv, h -> intf -> bytes_total));
  total_bytes_sent_printf (h); printf (" %s", percentage (h -> bytes_sent, h -> bytes_sent + h -> bytes_recv));
  total_bytes_recv_printf (h); printf (" %s", percentage (h -> bytes_recv, h -> bytes_sent + h -> bytes_recv));
  printf ("\n");

  if (h -> bytes_broadcast || h -> bytes_multicast)
    {
      printf ("  Unicast      : ");
      total_bytes_unicast_printf (h); printf (" %s", percentage (h -> bytes_sent + h -> bytes_recv - h -> bytes_broadcast - h -> bytes_multicast,
								 h -> bytes_sent + h -> bytes_recv));
      total_bytes_unicast_sent_printf (h); printf (" %s", percentage (h -> bytes_sent - h -> bytes_broadcast - h -> bytes_multicast,
								      h -> bytes_sent + h -> bytes_recv - h -> bytes_broadcast - h -> bytes_multicast));
      total_bytes_unicast_recv_printf (h); printf (" %s", percentage (h -> bytes_recv,
								      h -> bytes_sent + h -> bytes_recv - h -> bytes_broadcast - h -> bytes_multicast));
      printf ("\n");
    }

  if (h -> bytes_broadcast)
    {
      printf ("  Broadcast    : ");
      total_bytes_broadcast_printf (h); printf (" %s", percentage (h -> bytes_broadcast, h -> bytes_sent + h -> bytes_recv));
      printf ("\n");
    }

  if (h -> bytes_multicast)
    {
      printf ("  Multicast    : ");
      total_bytes_multicast_printf (h); printf (" %s", percentage (h -> bytes_multicast, h -> bytes_sent + h -> bytes_recv));
      printf ("\n");
    }
}


/* Print network usage in terms of packets */
void packets_distribution (host_t * h)
{
  printf ("\n");
  printf ("Packets             Total     %%         Sent    %%         Recv    %%\n");

  printf ("  Processed    : ");
  total_pkts_all_printf (h);  printf (" %s", percentage (h -> pkts_sent + h -> pkts_recv, h -> intf -> pkts_total));
  total_pkts_sent_printf (h); printf (" %s", percentage (h -> pkts_sent, h -> pkts_sent + h -> pkts_recv));
  total_pkts_recv_printf (h); printf (" %s", percentage (h -> pkts_recv, h -> pkts_sent + h -> pkts_recv));
  printf ("\n");

  if (h -> pkts_broadcast || h -> pkts_multicast)
    {
      printf ("  Unicast      : ");
      total_pkts_unicast_printf (h);      printf (" %s", percentage (h -> pkts_sent + h -> pkts_recv - h -> pkts_broadcast - h -> pkts_multicast,
								     h -> pkts_sent + h -> pkts_recv));
      total_pkts_unicast_sent_printf (h); printf (" %s", percentage (h -> pkts_sent - h -> pkts_broadcast - h -> pkts_multicast,
								     h -> pkts_sent + h -> pkts_recv - h -> pkts_broadcast - h -> pkts_multicast));
      total_pkts_unicast_recv_printf (h); printf (" %s", percentage (h -> pkts_recv,
								     h -> pkts_sent + h -> pkts_recv - h -> pkts_broadcast - h -> pkts_multicast));
      printf ("\n");
    }

  if (h -> pkts_broadcast)
    {
      printf ("  Broadcast    : ");
      total_pkts_broadcast_printf (h); printf (" %s", percentage (h -> pkts_broadcast, h -> pkts_sent + h -> pkts_recv));
      printf ("\n");
    }

  if (h -> pkts_multicast)
    {
      printf ("  Multicast    : ");
      total_pkts_multicast_printf (h); printf (" %s", percentage (h -> pkts_multicast, h -> pkts_sent + h -> pkts_recv));
      printf ("\n");
    }
}


/* Print network usage in terms of protocols */
void protocols_distribution (host_t * h)
{
  printf ("\n");
  printf ("Protocols           Bytes     %%         Sent    %%         Rcvd    %%        Pkts     %%         Sent    %%         Rcvd    %%\n");

  if (h -> bytes_ip_sent + h -> bytes_ip_recv)
    {
      printf ("   IP          : ");
      total_bytes_ip_all_printf (h);  printf (" %s", percentage (h -> bytes_ip_sent + h -> bytes_ip_recv, bytes_total (h)));
      total_bytes_ip_sent_printf (h); printf (" %s", percentage (h -> bytes_ip_sent, h -> bytes_ip_sent + h -> bytes_ip_recv));
      total_bytes_ip_recv_printf (h); printf (" %s", percentage (h -> bytes_ip_recv, h -> bytes_ip_sent + h -> bytes_ip_recv));
      total_pkts_ip_all_printf (h);   printf (" %s", percentage (h -> pkts_ip_sent + h -> pkts_ip_recv, pkts_total (h)));
      total_pkts_ip_sent_printf (h);  printf (" %s", percentage (h -> pkts_ip_sent, h -> pkts_ip_sent + h -> pkts_ip_recv));
      total_pkts_ip_recv_printf (h);  printf (" %s", percentage (h -> pkts_ip_recv, h -> pkts_ip_sent + h -> pkts_ip_recv));
      printf ("\n");
    }

  if (h -> bytes_arp_sent + h -> bytes_arp_recv)
    {
      printf ("   ARP         : ");
      total_bytes_arp_all_printf (h);  printf (" %s", percentage (h -> bytes_arp_sent + h -> bytes_arp_recv, bytes_total (h)));
      total_bytes_arp_sent_printf (h); printf (" %s", percentage (h -> bytes_arp_sent, h -> bytes_arp_sent + h -> bytes_arp_recv));
      total_bytes_arp_recv_printf (h); printf (" %s", percentage (h -> bytes_arp_recv, h -> bytes_arp_sent + h -> bytes_arp_recv));
      total_pkts_arp_all_printf (h);   printf (" %s", percentage (h -> pkts_arp_sent + h -> pkts_arp_recv, pkts_total (h)));
      total_pkts_arp_sent_printf (h);  printf (" %s", percentage (h -> pkts_arp_sent, h -> pkts_arp_sent + h -> pkts_arp_recv));
      total_pkts_arp_recv_printf (h);  printf (" %s", percentage (h -> pkts_arp_recv, h -> pkts_arp_sent + h -> pkts_arp_recv));
      printf ("\n");
    }

  if (h -> bytes_rarp_sent + h -> bytes_rarp_recv)
    {
      printf ("   RARP        : ");
      total_bytes_rarp_all_printf (h);  printf (" %s", percentage (h -> bytes_rarp_sent + h -> bytes_rarp_recv, bytes_total (h)));
      total_bytes_rarp_sent_printf (h); printf (" %s", percentage (h -> bytes_rarp_sent, h -> bytes_rarp_sent + h -> bytes_rarp_recv));
      total_bytes_rarp_recv_printf (h); printf (" %s", percentage (h -> bytes_rarp_recv, h -> bytes_rarp_sent + h -> bytes_rarp_recv));
      total_pkts_rarp_all_printf (h);   printf (" %s", percentage (h -> pkts_rarp_sent + h -> pkts_rarp_recv, pkts_total (h)));
      total_pkts_rarp_sent_printf (h);  printf (" %s", percentage (h -> pkts_rarp_sent, h -> pkts_rarp_sent + h -> pkts_rarp_recv));
      total_pkts_rarp_recv_printf (h);  printf (" %s", percentage (h -> pkts_rarp_recv, h -> pkts_rarp_sent + h -> pkts_rarp_recv));
      printf ("\n");
    }

  if (h -> bytes_non_ip_sent + h -> bytes_non_ip_recv)
    {
      printf ("   Non-IP      : ");
      total_bytes_non_ip_all_printf (h);  printf (" %s", percentage (h -> bytes_non_ip_sent + h -> bytes_non_ip_recv, bytes_total (h)));
      total_bytes_non_ip_sent_printf (h); printf (" %s", percentage (h -> bytes_non_ip_sent, h -> bytes_non_ip_sent + h -> bytes_non_ip_recv));
      total_bytes_non_ip_recv_printf (h); printf (" %s", percentage (h -> bytes_non_ip_recv, h -> bytes_non_ip_sent + h -> bytes_non_ip_recv));
      total_pkts_non_ip_all_printf (h);   printf (" %s", percentage (h -> pkts_non_ip_sent + h -> pkts_non_ip_recv, pkts_total (h)));
      total_pkts_non_ip_sent_printf (h);  printf (" %s", percentage (h -> pkts_non_ip_sent, h -> pkts_non_ip_sent + h -> pkts_non_ip_recv));
      total_pkts_non_ip_recv_printf (h);  printf (" %s", percentage (h -> pkts_non_ip_recv, h -> pkts_non_ip_sent + h -> pkts_non_ip_recv));
      printf ("\n");
    }

  if (h -> bytes_tcp_sent + h -> bytes_tcp_recv)
    {
      printf ("     TCP       : ");
      total_bytes_tcp_all_printf (h);  printf (" %s", percentage (h -> bytes_tcp_sent + h -> bytes_tcp_recv, bytes_ip_total (h)));
      total_bytes_tcp_sent_printf (h); printf (" %s", percentage (h -> bytes_tcp_sent, h -> bytes_tcp_sent + h -> bytes_tcp_recv));
      total_bytes_tcp_recv_printf (h); printf (" %s", percentage (h -> bytes_tcp_recv, h -> bytes_tcp_sent + h -> bytes_tcp_recv));
      total_pkts_tcp_all_printf (h);   printf (" %s", percentage (h -> pkts_tcp_sent + h -> pkts_tcp_recv, pkts_ip_total (h)));
      total_pkts_tcp_sent_printf (h);  printf (" %s", percentage (h -> pkts_tcp_sent, h -> pkts_tcp_sent + h -> pkts_tcp_recv));
      total_pkts_tcp_recv_printf (h);  printf (" %s", percentage (h -> pkts_tcp_recv, h -> pkts_tcp_sent + h -> pkts_tcp_recv));
      printf ("\n");
    }

  if (h -> bytes_udp_sent + h -> bytes_udp_recv)
    {
      printf ("     UDP       : ");
      total_bytes_udp_all_printf (h);  printf (" %s", percentage (h -> bytes_udp_sent + h -> bytes_udp_recv, bytes_ip_total (h)));
      total_bytes_udp_sent_printf (h); printf (" %s", percentage (h -> bytes_udp_sent, h -> bytes_udp_sent + h -> bytes_udp_recv));
      total_bytes_udp_recv_printf (h); printf (" %s", percentage (h -> bytes_udp_recv, h -> bytes_udp_sent + h -> bytes_udp_recv));
      total_pkts_udp_all_printf (h);   printf (" %s", percentage (h -> pkts_udp_sent + h -> pkts_udp_recv, pkts_ip_total (h)));
      total_pkts_udp_sent_printf (h);  printf (" %s", percentage (h -> pkts_udp_sent, h -> pkts_udp_sent + h -> pkts_udp_recv));
      total_pkts_udp_recv_printf (h);  printf (" %s", percentage (h -> pkts_udp_recv, h -> pkts_udp_sent + h -> pkts_udp_recv));
      printf ("\n");
    }

  if (h -> bytes_icmp_sent + h -> bytes_icmp_recv)
    {
      printf ("     ICMP      : ");
      total_bytes_icmp_all_printf (h);  printf (" %s", percentage (h -> bytes_icmp_sent + h -> bytes_icmp_recv, bytes_ip_total (h)));
      total_bytes_icmp_sent_printf (h); printf (" %s", percentage (h -> bytes_icmp_sent, h -> bytes_icmp_sent + h -> bytes_icmp_recv));
      total_bytes_icmp_recv_printf (h); printf (" %s", percentage (h -> bytes_icmp_recv, h -> bytes_icmp_sent + h -> bytes_icmp_recv));
      total_pkts_icmp_all_printf (h);   printf (" %s", percentage (h -> pkts_icmp_sent + h -> pkts_icmp_recv, pkts_ip_total (h)));
      total_pkts_icmp_sent_printf (h);  printf (" %s", percentage (h -> pkts_icmp_sent, h -> pkts_icmp_sent + h -> pkts_icmp_recv));
      total_pkts_icmp_recv_printf (h);  printf (" %s", percentage (h -> pkts_icmp_recv, h -> pkts_icmp_sent + h -> pkts_icmp_recv));
      printf ("\n");
    }

  if (h -> bytes_other_ip_sent + h -> bytes_other_ip_recv)
    {
      printf ("     Other-IP  : ");
      total_bytes_other_ip_all_printf (h);  printf (" %s", percentage (h -> bytes_other_ip_sent + h -> bytes_other_ip_recv, bytes_ip_total (h)));
      total_bytes_other_ip_sent_printf (h); printf (" %s", percentage (h -> bytes_other_ip_sent, h -> bytes_other_ip_sent + h -> bytes_other_ip_recv));
      total_bytes_other_ip_recv_printf (h); printf (" %s", percentage (h -> bytes_other_ip_recv, h -> bytes_other_ip_sent + h -> bytes_other_ip_recv));
      total_pkts_other_ip_all_printf (h);   printf (" %s", percentage (h -> pkts_other_ip_sent + h -> pkts_other_ip_recv, pkts_ip_total (h)));
      total_pkts_other_ip_sent_printf (h);  printf (" %s", percentage (h -> pkts_other_ip_sent, h -> pkts_other_ip_sent + h -> pkts_other_ip_recv));
      total_pkts_other_ip_recv_printf (h);  printf (" %s", percentage (h -> pkts_other_ip_recv, h -> pkts_other_ip_sent + h -> pkts_other_ip_recv));
      printf ("\n");
    }

#if defined(ROCCO)
  if (appletalk_bytes_all (h))
    printf ("     AppleTalk : "); appletalk_bytes_all_printf (h);  printf ("\n");
  if (decnet_bytes_all (h))
    printf ("     DecNET    : "); decnet_bytes_all_printf (h);     printf ("\n");
  if (dlc_bytes_all (h))
    printf ("     DLC       : "); dlc_bytes_all_printf (h);        printf ("\n");
  if (ipv6_bytes_all (h))
    printf ("     IPv6      : "); ipv6_bytes_all_printf (h);       printf ("\n");
  if (ipx_bytes_all (h))
    printf ("     IPX       : "); ipx_bytes_all_printf (h);        printf ("\n");
  if (netbios_bytes_all (h))
    printf ("     NetBIOS   : "); netbios_bytes_all_printf (h);    printf ("\n");
  if (osi_bytes_all (h))
    printf ("     OSI       : "); osi_bytes_all_printf (h);        printf ("\n");
  if (stp_bytes_all (h))
    printf ("     STP       : "); stp_bytes_all_printf (h);        printf ("\n");
#endif /* ROCCO */
}


/* Print network usage in terms of TCP protocols */
void tcp_protocols_distribution (host_t * h)
{
  if (h -> bytes_tcp_sent + h -> bytes_tcp_recv)
    {
      printf ("\n");
      printf ("TCP Protocols       Bytes     %%         Sent    %%         Rcvd    %%        Pkts     %%         Sent    %%         Rcvd    %%\n");

      if (h -> bytes_http_sent + h -> bytes_http_recv)
	{
	  printf ("       HTTP    : ");
	  total_bytes_http_all_printf (h);  printf (" %s", percentage (h -> bytes_http_sent + h -> bytes_http_recv, bytes_tcp_total (h)));
	  total_bytes_http_sent_printf (h); printf (" %s", percentage (h -> bytes_http_sent, h -> bytes_http_sent + h -> bytes_http_recv));
	  total_bytes_http_recv_printf (h); printf (" %s", percentage (h -> bytes_http_recv, h -> bytes_http_sent + h -> bytes_http_recv));
	  total_pkts_http_all_printf (h);   printf (" %s", percentage (h -> pkts_http_sent + h -> pkts_http_recv, pkts_tcp_total (h)));
	  total_pkts_http_sent_printf (h);  printf (" %s", percentage (h -> pkts_http_sent, h -> pkts_http_sent + h -> pkts_http_recv));
	  total_pkts_http_recv_printf (h);  printf (" %s", percentage (h -> pkts_http_recv, h -> pkts_http_sent + h -> pkts_http_recv));
	  printf ("\n");
	}

      if (h -> bytes_smtp_sent + h -> bytes_smtp_recv)
	{
	  printf ("       SMTP    : ");
	  total_bytes_smtp_all_printf (h);  printf (" %s", percentage (h -> bytes_smtp_sent + h -> bytes_smtp_recv, bytes_tcp_total (h)));
	  total_bytes_smtp_sent_printf (h); printf (" %s", percentage (h -> bytes_smtp_sent, h -> bytes_smtp_sent + h -> bytes_smtp_recv));
	  total_bytes_smtp_recv_printf (h); printf (" %s", percentage (h -> bytes_smtp_recv, h -> bytes_smtp_sent + h -> bytes_smtp_recv));
	  total_pkts_smtp_all_printf (h);   printf (" %s", percentage (h -> pkts_smtp_sent + h -> pkts_smtp_recv, pkts_tcp_total (h)));
	  total_pkts_smtp_sent_printf (h);  printf (" %s", percentage (h -> pkts_smtp_sent, h -> pkts_smtp_sent + h -> pkts_smtp_recv));
	  total_pkts_smtp_recv_printf (h);  printf (" %s", percentage (h -> pkts_smtp_recv, h -> pkts_smtp_sent + h -> pkts_smtp_recv));
	  printf ("\n");
	}

      if (h -> bytes_other_tcp_sent + h -> bytes_other_tcp_recv)
	{
	  printf ("       Other   : ");
	  total_bytes_other_tcp_all_printf (h);  printf (" %s", percentage (h -> bytes_other_tcp_sent + h -> bytes_other_tcp_recv, bytes_tcp_total (h)));
	  total_bytes_other_tcp_sent_printf (h); printf (" %s", percentage (h -> bytes_other_tcp_sent, h -> bytes_other_tcp_sent + h -> bytes_other_tcp_recv));
	  total_bytes_other_tcp_recv_printf (h); printf (" %s", percentage (h -> bytes_other_tcp_recv, h -> bytes_other_tcp_sent + h -> bytes_other_tcp_recv));
	  total_pkts_other_tcp_all_printf (h);   printf (" %s", percentage (h -> pkts_other_tcp_sent + h -> pkts_other_tcp_recv, pkts_tcp_total (h)));
	  total_pkts_other_tcp_sent_printf (h);  printf (" %s", percentage (h -> pkts_other_tcp_sent, h -> pkts_other_tcp_sent + h -> pkts_other_tcp_recv));
	  total_pkts_other_tcp_recv_printf (h);  printf (" %s", percentage (h -> pkts_other_tcp_recv, h -> pkts_other_tcp_sent + h -> pkts_other_tcp_recv));
	  printf ("\n");
	}
    }
}


/* Format and print data from the internal hosts cache */
void hostprintf (host_t * h, int argc, char * argv [], char fsep)
{
  /* G N U  F o r m a t t i n g  o p t i o n s */
  static struct option const long_options [] =
    {
      /* Administrative [range 100 - 119] */

      { "label",                  required_argument, NULL, 100 },

      /* Identifiers */

      { "interface",              no_argument,       NULL, 101 },
      { "datalink",               no_argument,       NULL, 102 },
      { "mac-address",            no_argument,       NULL, 103 },
      { "ip-address",             no_argument,       NULL, 104 },
      { "hostname",               optional_argument, NULL, 105 },
      { "host-numeric",           optional_argument, NULL, 106 },
      { "host-identifier",        optional_argument, NULL, 107 },
      { "host-ipless",            optional_argument, NULL, 108 },
      { "vendor-name",            optional_argument, NULL, 109 },
      { "os-name",                optional_argument, NULL, 110 },
      { "domain-name",            optional_argument, NULL, 111 },
      { "first-seen",             no_argument,       NULL, 112 },
      { "last-seen",              no_argument,       NULL, 113 },
      { "age-last",               no_argument,       NULL, 114 },
      { "age-uptime",             no_argument,       NULL, 115 },

      /* Total bytes (sent + received) for all protocols [range 120 - 139] */

      { "total-bytes-all",        no_argument,       NULL, 120 },
      { "broadcast-bytes",        no_argument,       NULL, 121 },
      { "multicast-bytes",        no_argument,       NULL, 122 },
      { "ip-bytes-all",           no_argument,       NULL, 123 },
      { "ip-broadcast-bytes",     no_argument,       NULL, 124 },
      { "ip-multicast-bytes",     no_argument,       NULL, 125 },
      { "arp-bytes-all",          no_argument,       NULL, 126 },
      { "rarp-bytes-all",         no_argument,       NULL, 127 },
      { "non-ip-bytes-all",       no_argument,       NULL, 128 },
      { "tcp-bytes-all",          no_argument,       NULL, 129 },
      { "udp-bytes-all",          no_argument,       NULL, 130 },
      { "icmp-bytes-all",         no_argument,       NULL, 131 },
      { "other-ip-bytes-all",     no_argument,       NULL, 132 },

      /* Total bytes sent for all protocols [range 140 - 159] */

      { "total-bytes-sent",       no_argument,       NULL, 140 },
      { "ip-bytes-sent",          no_argument,       NULL, 141 },
      { "arp-bytes-sent",         no_argument,       NULL, 142 },
      { "rarp-bytes-sent",        no_argument,       NULL, 143 },
      { "non-ip-bytes-sent",      no_argument,       NULL, 144 },
      { "tcp-bytes-sent",         no_argument,       NULL, 145 },
      { "udp-bytes-sent",         no_argument,       NULL, 146 },
      { "icmp-bytes-sent",        no_argument,       NULL, 147 },
      { "other-ip-bytes-sent",    no_argument,       NULL, 148 },

      { "bytes-sent-to-local",    no_argument,       NULL, 151 },
      { "bytes-sent-to-remote",   no_argument,       NULL, 152 },

      /* Total bytes received for all protocols [range 160 - 179] */

      { "total-bytes-recv",       no_argument,       NULL, 160 },
      { "ip-bytes-recv",          no_argument,       NULL, 161 },
      { "arp-bytes-recv",         no_argument,       NULL, 162 },
      { "rarp-bytes-recv",        no_argument,       NULL, 163 },
      { "non-ip-bytes-recv",      no_argument,       NULL, 164 },
      { "tcp-bytes-recv",         no_argument,       NULL, 165 },
      { "udp-bytes-recv",         no_argument,       NULL, 166 },
      { "icmp-ip-bytes-recv",     no_argument,       NULL, 167 },
      { "other-ip-bytes-recv",    no_argument,       NULL, 168 },

      { "bytes-recv-from-local",  no_argument,       NULL, 170 },
      { "bytes-recv-from-remote", no_argument,       NULL, 171 },

      /* Total packets (sent + received) for all protocols [range 180 - 199] */

      { "total-pkts-all",         no_argument,       NULL, 180 },
      { "broadcast-pkts-sent",    no_argument,       NULL, 181 },
      { "multicast-pkts-sent",    no_argument,       NULL, 182 },
      { "ip-pkts-all",            no_argument,       NULL, 183 },
      { "ip-broadcast-pkts-sent", no_argument,       NULL, 184 },
      { "ip-multicast-pkts-sent", no_argument,       NULL, 185 },
      { "arp-pkts-all",           no_argument,       NULL, 186 },
      { "rarp-pkts-all",          no_argument,       NULL, 187 },
      { "non-ip-pkts-all",        no_argument,       NULL, 188 },
      { "tcp-pkts-all",           no_argument,       NULL, 189 },
      { "udp-pkts-all",           no_argument,       NULL, 190 },
      { "icmp-pkts-all",          no_argument,       NULL, 191 },
      { "other-ip-pkts-all",      no_argument,       NULL, 192 },

      /* Total packets sent for all protocols [range 200 - 219] */

      { "total-pkts-sent",        no_argument,       NULL, 200 },
      { "ip-pkts-sent",           no_argument,       NULL, 201 },
      { "arp-pkts-sent",          no_argument,       NULL, 202 },
      { "rarp-pkts-sent",         no_argument,       NULL, 203 },
      { "non-ip-pkts-sent",       no_argument,       NULL, 204 },
      { "tcp-pkts-sent",          no_argument,       NULL, 205 },
      { "udp-pkts-sent",          no_argument,       NULL, 206 },
      { "icmp-pkts-sent",         no_argument,       NULL, 207 },
      { "other-ip-pkts-sent",     no_argument,       NULL, 208 },

      { "pkts-sent-to-local",     no_argument,       NULL, 209 },
      { "pkts-sent-to-remote",    no_argument,       NULL, 210 },

      /* Total packets received for all protocols [range 220 - 239] */

      { "total-pkts-recv",        no_argument,       NULL, 220 },
      { "ip-pkts-recv",           no_argument,       NULL, 221 },
      { "arp-pkts-recv",          no_argument,       NULL, 222 },
      { "rarp-pkts-recv",         no_argument,       NULL, 223 },
      { "non-ip-pkts-recv",       no_argument,       NULL, 224 },
      { "tcp-pkts-recv",          no_argument,       NULL, 225 },
      { "udp-pkts-recv",          no_argument,       NULL, 226 },
      { "icmp-pkts-recv",         no_argument,       NULL, 227 },
      { "other-ip-pkts-recv",     no_argument,       NULL, 228 },

      { "pkts-recv-from-local",   no_argument,       NULL, 230 },
      { "pkts-recv-from-remote",  no_argument,       NULL, 231 },

      { NULL,                     0,                 NULL, 0 }
    };

  int option;
  char tsep = '\0';

  char fmt [1024];
  char label [1024];
  int width = 0;

  /* table separator */
  if (tsep)
    printf ("%c", tsep);

  /* Parse command line options */
  optind = 0;
  optarg = NULL;
  while ((option = getopt_long (argc, argv, "", long_options, NULL)) != -1)
    {
      width = 0;
      switch (option)
	{
	case 100:    /* Label */
	  sscanf (optarg, "%[^[][%d][^]]]", label, & width);
	  printf ("%s", center (fmt, label, width ? width : strlen (label)));
	  break;

	case 101: interface_printf (h);                  break; /* Network interface name (FIXED_LEN_NAME)     */
	case 102: datalink_printf (h);                   break; /* Data-link type                              */
	case 103: mac_printf (h);                        break; /* MAC address (FIXED_LEN_MAC bytes long)      */
	case 104: ip_printf (h);                         break; /* IP address (FIXED_LEN_IP bytes long)        */
	case 105: hostname_printf (h, optarg);           break; /* Hostname Address (Symbolic)                 */
	case 106: numeric_id_printf (h, optarg);         break; /* Host numeric identifier                     */
	case 107: unique_id_printf (h, optarg);          break; /* Host unique identifier                      */
	case 108: ipless_id_printf (h, optarg);          break; /* Host unique identifier for IP-Less          */
	case 109: vendor_printf (h, optarg);             break; /* NIC Vendor Name resolved via IEEE database  */
	case 110: os_system_printf (h, optarg);          break; /* OS System Name resolved via fingerprint     */
	case 111: domain_printf (h, optarg);             break; /* Domain name                                 */
	case 112: firstseen_printf (h);                  break; /* First Seen (fixed size left aligned)        */
	case 113: lastseen_printf (h);                   break; /* Last Seen (fixed size left aligned)         */
	case 114: age_last_printf (h);                   break; /* Age last-like format                        */
	case 115: age_uptime_printf (h);                 break; /* Age uptime-like format                      */

	case 120: total_bytes_all_printf (h);            break; /* Total bytes all (sent + received)           */
	case 121: total_bytes_broadcast_printf (h);      break; /* Total Broadcast bytes sent                  */
	case 122: total_bytes_multicast_printf (h);      break; /* Total Multicast bytes sent                  */
	case 123: total_bytes_ip_all_printf (h);         break; /* Total IP bytes all (sent + received)        */
	case 124: total_bytes_ip_broadcast_printf (h);   break; /* Total IP Broadcast bytes sent               */
	case 125: total_bytes_ip_multicast_printf (h);   break; /* Total IP Multicast bytes sent               */
	case 126: total_bytes_arp_all_printf (h);        break; /* Total ARP bytes all (sent + received)       */
	case 127: total_bytes_rarp_all_printf (h);       break; /* Total RARP bytes all (sent + received)      */
	case 128: total_bytes_non_ip_all_printf (h);     break; /* Total Non-IP bytes all (sent + received)    */
	case 129: total_bytes_tcp_all_printf (h);        break; /* Total TCP bytes all (sent + received)       */
	case 130: total_bytes_udp_all_printf (h);        break; /* Total UDP bytes all (sent + received)       */
	case 131: total_bytes_icmp_all_printf (h);       break; /* Total ICMP bytes all (sent + received)      */
	case 132: total_bytes_other_ip_all_printf (h);   break; /* Total Other-IP bytes all (sent + received)  */

	case 140: total_bytes_sent_printf (h);           break; /* Total bytes sent                            */
	case 141: total_bytes_ip_sent_printf (h);        break; /* Total IP bytes sent                         */
	case 142: total_bytes_arp_sent_printf (h);       break; /* Total ARP bytes sent                        */
	case 143: total_bytes_rarp_sent_printf (h);      break; /* Total RARP bytes sent                       */
	case 144: total_bytes_non_ip_sent_printf (h);    break; /* Total Non-IP bytes sent                     */
	case 145: total_bytes_tcp_sent_printf (h);       break; /* Total TCP bytes sent                        */
	case 146: total_bytes_udp_sent_printf (h);       break; /* Total UDP bytes sent                        */
	case 147: total_bytes_icmp_sent_printf (h);      break; /* Total ICMP bytes sent                       */
	case 148: total_bytes_other_ip_sent_printf (h);  break; /* Total Other-IP bytes sent                   */

	case 151:                                        break; /* Total bytes sent to local network           */
	case 152:                                        break; /* Total bytes sent to remote networks         */

	case 160: total_bytes_recv_printf (h);           break; /* Total bytes received                        */
	case 161: total_bytes_ip_recv_printf (h);        break; /* Total IP bytes received                     */
	case 162: total_bytes_arp_recv_printf (h);       break; /* Total ARP bytes received                    */
	case 163: total_bytes_rarp_recv_printf (h);      break; /* Total RARP bytes received                   */
	case 164: total_bytes_non_ip_recv_printf (h);    break; /* Total Non-IP bytes received                 */
	case 165: total_bytes_tcp_recv_printf (h);       break; /* Total TCP bytes received                    */
	case 166: total_bytes_udp_recv_printf (h);       break; /* Total UDP bytes received                    */
	case 167: total_bytes_icmp_recv_printf (h);      break; /* Total ICMP bytes received                   */
	case 168: total_bytes_other_ip_recv_printf (h);  break; /* Total Other-IP bytes received               */

	case 169:                                        break; /* Total bytes received from local network     */
	case 170:                                        break; /* Total bytes received from remote networks   */

	case 180: total_pkts_all_printf (h);             break; /* Total packets all (sent + received)         */
	case 181: total_pkts_broadcast_printf (h);       break; /* Total Broadcast packets sent                */
	case 182: total_pkts_multicast_printf (h);       break; /* Total Multicast packets all sent            */
	case 183: total_pkts_ip_all_printf (h);          break; /* Total IP packets all (sent + received)      */
	case 184: total_pkts_ip_broadcast_printf (h);    break; /* Total IP Broadcast packets sent             */
	case 185: total_pkts_ip_multicast_printf (h);    break; /* Total IP Multicast packets sent             */
	case 186: total_pkts_arp_all_printf (h);         break; /* Total ARP packets all (sent + received)     */
	case 187: total_pkts_rarp_all_printf (h);        break; /* Total RARP packets all (sent + received)    */
	case 188: total_pkts_non_ip_all_printf (h);      break; /* Total Non-IP packets all (sent + received)  */
	case 189: total_pkts_tcp_all_printf (h);         break; /* Total TCP packets all (sent + received)     */
	case 190: total_pkts_udp_all_printf (h);         break; /* Total UDP packets all (sent + received)     */
	case 191: total_pkts_icmp_all_printf (h);        break; /* Total ICMP packets all (sent + received)    */
	case 192: total_pkts_other_ip_all_printf (h);    break; /* Total Other-IP packets all (sent + received)*/

	case 200: total_pkts_sent_printf (h);            break; /* Total packets sent                          */
	case 201: total_pkts_ip_sent_printf (h);         break; /* Total IP packets sent                       */
	case 202: total_pkts_arp_sent_printf (h);        break; /* Total ARP packets sent                      */
	case 203: total_pkts_rarp_sent_printf (h);       break; /* Total RARP packets sent                     */
	case 204: total_pkts_non_ip_sent_printf (h);     break; /* Total Non-IP packets sent                   */
	case 205: total_pkts_tcp_sent_printf (h);        break; /* Total TCP packets sent                      */
	case 206: total_pkts_udp_sent_printf (h);        break; /* Total UDP packets sent                      */
	case 207: total_pkts_icmp_sent_printf (h);       break; /* Total ICMP packets sent                     */
	case 208: total_pkts_other_ip_sent_printf (h);   break; /* Total Other-IP packets sent                 */

	case 209:                                        break; /* Total packets sent to local network         */
	case 210:                                        break; /* Total packets sent to remote networks       */

	case 220: total_pkts_recv_printf (h);            break; /* Total packets received                      */
	case 221: total_pkts_ip_recv_printf (h);         break; /* Total IP packets received                   */
	case 222: total_pkts_arp_recv_printf (h);        break; /* Total ARP packets received                  */
	case 223: total_pkts_rarp_recv_printf (h);       break; /* Total RARP packets received                 */
	case 224: total_pkts_non_ip_recv_printf (h);     break; /* Total Non-IP packets received               */
	case 225: total_pkts_tcp_recv_printf (h);        break; /* Total TCP packets received                  */
	case 226: total_pkts_udp_recv_printf (h);        break; /* Total UDP packets received                  */
	case 227: total_pkts_icmp_recv_printf (h);       break; /* Total ICMP packets received                 */
	case 228: total_pkts_other_ip_recv_printf (h);   break; /* Total Other-IP packets received             */

	case 229:                                        break; /* Total packets received from local network   */
	case 230:                                        break; /* Total packets received from remote networks */

	default: printf ("%s: unknown option '%d'", argv [0], option); break;
	}

      /* field separator */
      if (fsep)
	printf ("%c", fsep);
    }
}
