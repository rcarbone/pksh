/*
 * pksh - The Packet Shell
 *
 * R. Carbone (rocco@tecsiel.it)
 * 2003, 2008-2009, 2022
 *
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 */


#pragma once


/* System headers */
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <pthread.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <libgen.h>
#include <getopt.h>

/* pcap header */
#include <pcap.h>

/* Project headers */
#include "rlibc.h"
#include "hash.h"


/* Constants */

/* The name of the game */
#define PKSH_PACKAGE      "pksh"
#define PKSH_VERSION      "0.3.0"
#define PKSH_AUTHOR       "R. Carbone (rocco@tecsiel.it)"
#define PKSH_RELEASED     __DATE__
#define PKSH_LICENSE_ID   "BSD-2-Clause-FreeBSD"
#define PKSH_LICENSE      "BSD 2-Clause FreeBSD License"
#define PKSH_LICENSE_URL  "http://www.freebsd.org/copyright/freebsd-license.html"


/* Macros for min/max */
#if !defined MIN
# define MIN(a,b) (a < b ? a : b)
#endif
#if !defined MAX
# define MAX(a,b) (a > b ? a : b)
#endif

#define MAX_NUM_DEVICES   128

#define DEFAULT_SNAPSHOT  1514  /* Ethernet interface MTU is 1500 bytes not including data-link header (14 bytes) */
#define DEFAULT_TIMEOUT   100
#define DEFAULT_MAXCOUNT  0     /* 0 means unlimited */

/* Interface status */
#define INTERFACE_DOWN    0     /* not yet enabled via pcap          */
#define INTERFACE_READY   1     /* ready for packet sniffing         */
#define INTERFACE_ENABLED 2     /* packet capturing currently active */

/* Default size for the hash tables */
#define DEFAULT_HW_SIZE   512   /* initial hash table size for hardware identifiers */
#define DEFAULT_IP_SIZE   2048  /* initial hash table size for IP addresses         */
#define DEFAULT_HOST_SIZE 4096  /* initial hash table size for hostnames            */

#define LOOPBACK_ADDR     "127.0.0.1"
#define NULL_IPADDR       "0.0.0.0"

/* The 'ettercap' signatures are prefixed by 28 digits coded as WWWW:MSS:TTL:WS:S:N:D:T:F:LL */
#define FPLEN    30

/* Characters for tables rendering */
#define COL_BEGIN        '|'
#define COL_SEP          ' '
#define COL_END          '|'


/* Typedefs */


/* Define a counter */
typedef unsigned long counter_t;

/* Define a sorting function */
typedef int sf (const void * _a, const void * _b);


/* The structure contains information on the commands the application can understand */
typedef struct
{
  char * name;                                 /* builtin name      */
  char * brief;                                /* brief description */
  char * synopsis;                             /* usage synopsis    */
  char * description;                          /* long description  */
  int (* func) (int argc, char * argv []);

} pksh_cmd_t;


/* All that is needed to handle a pcap-aware interface */
typedef struct
{
  char * name;                  /* interface name (eg. eth0)                              */
  int status;                   /* the status of the interface                            */

  /* pcap related */
  int snapshot;                 /* maximum # of bytes to capture foreach pkt              */
  int promiscuous;              /* flag to set to promiscuous mode                        */
  int timeout;                  /* read timeout in msec                                   */
  int maxcount;                 /* # of packets to process (0 means unlimited)            */
  char * filter;                /* user defined filter expression (if any)                */
  pcap_t * pcap;                /* pcap handle as returned by pcap_open_live()            */
  int datalink;                 /* data-link encapsulation type (see DLT_* in pcap-bpf.h) */
  bpf_u_int32 pcapnetwork;      /* network number (in host binary format)                 */
  bpf_u_int32 pcapnetmask;      /* network netmask (in host binary format)                */

  /* Interface identifiers for fast host addresses computation */
  uint32_t ipbin;               /* internet address (in host binary format)               */
  uint32_t netmaskbin;          /* network mask (in host binary format)                   */
  uint32_t networkbin;          /* network address (in host binary format)                */
  uint32_t broadcastbin;        /* broadcast address (in host binary format)              */

  /* Interface identifiers for humans */
  char * hwaddr;                /* HW address (resolved for humans)                       */
  char * ipaddr;                /* IP address (in dot notation xxx.xxx.xxx.xxx)           */
  char * hostname;              /* hostname resolved for humans                           */
  char * network;               /* Local network (in dot notation xxx.xxx.xxx.xxx)        */
  char * netmask;               /* Network netmask (in dot notation xxx.xxx.xxx.xxx)      */
  char * broadcast;             /* Broadcast address (in dot notation xxx.xxx.xxx.xxx)    */
  int mtu;                      /* Maximum transmit unit                                  */

  pthread_t tid;                /* unique identifier of thread dedicated sniffer          */

  /* Time */
  struct timeval started;       /* time interface was enabled to look at pkts             */
  struct timeval firstpkt;      /* time first packet was captured                         */
  struct timeval lastpkt;       /* time last packet was captured                          */

  struct hash_table hwnames;    /* the hash table with all viewed interface identifiers   */
  struct hash_table ipnames;    /* the hash table with all viewed IP addresses            */
  struct hash_table hostnames;  /* the hash table with all viewed hostnames               */

  /* Bytes and Packets counters */
  int shortest;
  int longest;

  /* Packets distribution by size */
  counter_t upto75;   counter_t upto150;  counter_t upto225;  counter_t upto300;  counter_t upto375;  counter_t upto450;  counter_t upto525;
  counter_t upto600;  counter_t upto675;  counter_t upto750;  counter_t upto825;  counter_t upto900;  counter_t upto975;  counter_t upto1050;
  counter_t upto1125; counter_t upto1200; counter_t upto1275; counter_t upto1350; counter_t upto1425; counter_t upto1514; counter_t above1514;

  /* Counters for all the supported network interface data-links */
  counter_t headers_total;      /* length in bytes of all headers over data-link layer    */
  counter_t bytes_total;        /* length in bytes of all data (including headers)        */
  counter_t pkts_total;         /* total # of packets received from data-link layer       */

  /* Counters for all the others (currently unsupported) data-links */
  counter_t bytes_other;
  counter_t pkts_other;

  /* Broadcast and multicast counters over the interface (unicast = tot - broadcast - multicast) */
  counter_t bytes_broadcast;
  counter_t pkts_broadcast;
  counter_t bytes_multicast;
  counter_t pkts_multicast;

  /* IP counters */
  counter_t headers_ip;         /* length in bytes of IP headers only                    */
  counter_t bytes_ip;           /* length in bytes of IP data (including headers)        */
  counter_t pkts_ip;            /* total # of IP packets received from data-link layer   */

  /* IP TTL distribution by size */
  counter_t ttl_upto32;  counter_t ttl_upto64;  counter_t ttl_upto128; counter_t ttl_upto160;
  counter_t ttl_upto192; counter_t ttl_upto224; counter_t ttl_above224;

  /* Broadcast and multicast over IP counters (unicast = tot - broadcast - multicast) */
  counter_t bytes_ip_broadcast;
  counter_t pkts_ip_broadcast;
  counter_t bytes_ip_multicast;
  counter_t pkts_ip_multicast;
  counter_t bytes_ip_all_hosts; /* bytes sent to all hosts over IP                       */
  counter_t pkts_ip_all_hosts;  /* pkts sent to all hosts over IP                        */

  /* ARP counters */
  counter_t bytes_arp;
  counter_t pkts_arp;

  /* RARP counters */
  counter_t bytes_rarp;
  counter_t pkts_rarp;

  /* Counters for Non-IP Protocols */
  counter_t bytes_non_ip;
  counter_t pkts_non_ip;

  /* TCP over IP counters */
  counter_t headers_tcp;        /* length in bytes of TCP headers only                   */
  counter_t bytes_tcp;          /* length in bytes of TCP data (including headers)       */
  counter_t pkts_tcp;           /* total # of TCP packets received from data-link layer  */

  /* UDP over IP counters */
  counter_t bytes_udp;
  counter_t pkts_udp;

  /* ICMP over IP counters */
  counter_t bytes_icmp;
  counter_t pkts_icmp;

  /* Other (currently unsupported protocols) over IP counters */
  counter_t bytes_other_ip;
  counter_t pkts_other_ip;

  /* Other (currently unsupported protocols) over TCP counters */
  counter_t bytes_other_tcp;
  counter_t pkts_other_tcp;

  /* HTTP over TCP counters */
  counter_t bytes_http;
  counter_t pkts_http;

  /* SMTP over TCP counters */
  counter_t bytes_smtp;
  counter_t pkts_smtp;

} interface_t;


/* Define a protocol header */
typedef struct
{
  const u_char * protocol;  /* encapsulating protocol    */
  struct timeval * ts;      /* time stamp                */
  unsigned len;             /* length of this packet     */
  unsigned caplen;          /* length of portion present */

} header_t;


/* Define a host (all pointers to hash table items are simply referenced rather than locally copied) */
typedef struct
{
  interface_t * intf;             /* reference to interface used to send/recv packets      */

  struct timeval first;           /* time it was first seen                                */
  struct timeval last;            /* time it was last seen                                 */

  /* Interface identifiers for fast host addresses computation */
  struct in_addr ip;              /* internet address (in host binary format)              */  /* FIXME: should be removed? */

  /* Interface identifiers for humans */
  char * hwaddress;               /* hw address human readable (xx:xx:xx:xx:xx:xx)         */
  char * vendor;                  /* organization name for the hw interface                */
  char * ipaddr;                  /* internet address (in dot notation for humans)         */
  char * hostname;                /* full qualified hostname resolved for humans           */
  char fingerprint [FPLEN];       /* OS passive fingerprint calculated by IP/TCP frames    */
  char * system;                  /* Unique system id revolved by OS fingerprints database */

  /* Sent bytes counters */
  counter_t bytes_sent;           /* tot # of bytes sent over the interface                */
  counter_t bytes_broadcast;      /* tot # of broadcast bytes sent over the interface      */
  counter_t bytes_multicast;      /* tot # of multicast bytes sent over the interface      */
  counter_t bytes_sent_local;     /* tot # of bytes sent to local network(s)               */
  counter_t bytes_sent_foreign;   /* tot # of bytes sent to foreign  networks              */

  /* Sent over data-link bytes counters */
  counter_t bytes_ip_sent;        /* tot # of IP bytes sent over the interface             */
  counter_t bytes_ip_broadcast;   /* tot # of IP broadcast bytes sent over the interface   */
  counter_t bytes_ip_multicast;   /* tot # of IP multicast bytes sent over the interface   */
  counter_t bytes_ip_all_hosts;   /* tot # of bytes sent to all hosts                      */
  counter_t bytes_arp_sent;       /* tot # of ARP bytes sent over the interface            */
  counter_t bytes_rarp_sent;      /* tot # of RARP bytes sent over the interface           */
  counter_t bytes_non_ip_sent;    /* tot # of Non-IP bytes sent over the interface         */

  /* IP Time To Live */
  short ttl_shortest;
  short ttl_longest;

  /* Sent over IP bytes counters */
  counter_t bytes_tcp_sent;       /* tot # of TCP bytes sent over the interface            */
  counter_t bytes_udp_sent;       /* tot # of UDP bytes sent over the interface            */
  counter_t bytes_icmp_sent;      /* tot # of UDP bytes sent over the interface            */
  counter_t bytes_other_ip_sent;  /* tot # of Other-IP bytes sent over the interface       */

  /* Sent over TCP bytes counters */
  counter_t bytes_http_sent;      /* tot # of HTTP bytes sent over the interface           */
  counter_t bytes_smtp_sent;      /* tot # of SMTP bytes sent over the interface           */
  counter_t bytes_other_tcp_sent; /* tot # of Other-TCP bytes sent over the interface      */

  /* Received bytes counters */
  counter_t bytes_recv;           /* tot # of bytes received from the interface            */
  counter_t bytes_recv_local;     /* tot # of bytes received from local network(s)         */
  counter_t bytes_recv_foreign;   /* tot # of bytes received from foreign networks         */

  /* Received from data-link bytes counters */
  counter_t bytes_ip_recv;        /* tot # of IP bytes received from the interface         */
  counter_t bytes_arp_recv;       /* tot # of ARP bytes received from the interface        */
  counter_t bytes_rarp_recv;      /* tot # of RARP bytes received from the interface       */
  counter_t bytes_non_ip_recv;    /* tot # of Non-IP bytes received from the interface     */

  /* Received over IP bytes counters */
  counter_t bytes_tcp_recv;       /* tot # of TCP bytes received from the interface        */
  counter_t bytes_udp_recv;       /* tot # of UDP bytes received from the interface        */
  counter_t bytes_icmp_recv;      /* tot # of UDP bytes received from the interface        */
  counter_t bytes_other_ip_recv;  /* tot # of Other-IP bytes received from the interface   */

  /* Received over TCP bytes counters */
  counter_t bytes_http_recv;      /* tot # of HTTP bytes received from the interface       */
  counter_t bytes_smtp_recv;      /* tot # of SMTP bytes received from the interface       */
  counter_t bytes_other_tcp_recv; /* tot # of Other-TCP bytes received from the interface  */

  /* Sent packets counters */
  counter_t pkts_sent;            /* tot # of packets sent over the interface              */
  counter_t pkts_broadcast;       /* tot # of broadcast packets sent over the interface    */
  counter_t pkts_multicast;       /* tot # of multicast packets sent over the interface    */
  counter_t pkts_sent_local;      /* tot # of packets sent to local network(s)             */
  counter_t pkts_sent_foreign;    /* tot # of packets sent to foreign  networks            */

  /* Sent over data-link packets counters */
  counter_t pkts_ip_sent;         /* tot # of IP packets sent over the interface           */
  counter_t pkts_ip_broadcast;    /* tot # of broadcast packets sent over the interface    */
  counter_t pkts_ip_multicast;    /* tot # of multicast packets sent over the interface    */
  counter_t pkts_ip_all_hosts;    /* tot # of packets sent to all hosts                    */
  counter_t pkts_arp_sent;        /* tot # of ARP packets sent over the interface          */
  counter_t pkts_rarp_sent;       /* tot # of RARP packets sent over the interface         */
  counter_t pkts_non_ip_sent;     /* tot # of Non-IP packets sent over the interface       */

  /* Sent over IP packets counters */
  counter_t pkts_tcp_sent;        /* tot # of TCP packets sent over the interface          */
  counter_t pkts_udp_sent;        /* tot # of UDP packets sent over the interface          */
  counter_t pkts_icmp_sent;       /* tot # of UDP packets sent over the interface          */
  counter_t pkts_other_ip_sent;   /* tot # of Other-IP packets sent over the interface     */

  /* Sent over TCP packets counters */
  counter_t pkts_http_sent;      /* tot # of HTTP packets sent over the interface          */
  counter_t pkts_smtp_sent;      /* tot # of SMTP packets sent over the interface          */
  counter_t pkts_other_tcp_sent; /* tot # of Other-TCP packets sent over the interface     */

  /* Received packets counters */
  counter_t pkts_recv;            /* tot # of packets recv from the interface              */
  counter_t pkts_recv_local;      /* tot # of packets received from local network(s)       */
  counter_t pkts_recv_foreign;    /* tot # of packets received from foreign networks       */

  /* Sent over data-link packets counters */
  counter_t pkts_ip_recv;         /* tot # of IP packets received from the interface       */
  counter_t pkts_arp_recv;        /* tot # of ARP packets received from the interface      */
  counter_t pkts_rarp_recv;       /* tot # of RARP packets received from the interface     */
  counter_t pkts_non_ip_recv;     /* tot # of Non-IP packets received from the interface   */

  /* Received over IP packets counters */
  counter_t pkts_tcp_recv;        /* tot # of TCP packets received from the interface      */
  counter_t pkts_udp_recv;        /* tot # of UDP packets received from the interface      */
  counter_t pkts_icmp_recv;       /* tot # of UDP packets received from the interface      */
  counter_t pkts_other_ip_recv;   /* tot # of Other-IP packets received from the interface */

  /* Received over TCP packets counters */
  counter_t pkts_http_recv;      /* tot # of HTTP packets received from the interface      */
  counter_t pkts_smtp_recv;      /* tot # of SMTP packets received from the interface      */
  counter_t pkts_other_tcp_recv; /* tot # of Other-TCP packets received from the interface */

  /* Throughput */
  int bytes_current;
  int bytes_average;
  int bytes_peak;

  int pkts_current;
  int pkts_average;
  int pkts_peak;

} host_t;


/* Define a counter function */
typedef void cf (interface_t * intf, header_t * h, u_char * p, host_t * srchost, host_t * dsthost);


/* Define a protocol with its parser/counter function */
typedef struct
{
  int id;          /* protocol id as viewed in the protocol header */
  cf * counter;    /* the counter function                         */

} protocol_t;


/*
 * The structure to keep run-time parameters all in one,
 * defined in order to have a static, local and unique
 * container that collects all the global variables
 */
typedef struct
{
  char * progname;           /* the name of the game          */
  struct timeval boottime;   /* the time program started      */
  char * prompt;             /* user prompt                   */
  char * pcolor;             /* default ansi-color for prompt */
  bool   bell;               /* ring the bell after execution */

  bool   initialized;        /* has ocilib been initialized?  */

} pksh_run_t;


/* === Variables === */

/* A global variable defined and initialized in file init.c */
extern pksh_run_t pksh_run;

/* Public variables in file interface.c */
extern interface_t ** interfaces;


/* === Helpers === */
extern pksh_cmd_t cmd_help;
extern pksh_cmd_t cmd_about;
extern pksh_cmd_t cmd_version;
extern pksh_cmd_t cmd_license;
#if defined(ROCCO)
extern pksh_cmd_t cmd_when;
#endif /* ROCCO */

/* === Network Interfaces === */
extern pksh_cmd_t cmd_dev;
extern pksh_cmd_t cmd_open;
extern pksh_cmd_t cmd_close;
extern pksh_cmd_t cmd_enable;
extern pksh_cmd_t cmd_status;
extern pksh_cmd_t cmd_uptime;
extern pksh_cmd_t cmd_filter;
extern pksh_cmd_t cmd_swap;

/* === Viewers === */
extern pksh_cmd_t cmd_packets;
extern pksh_cmd_t cmd_bytes;
extern pksh_cmd_t cmd_hosts;
extern pksh_cmd_t cmd_arp;
extern pksh_cmd_t cmd_finger;
extern pksh_cmd_t cmd_last;
extern pksh_cmd_t cmd_who;
extern pksh_cmd_t cmd_protocols;
extern pksh_cmd_t cmd_services;
extern pksh_cmd_t cmd_throughput;


/* === Functions === */

/* Public functions in file cache.c */
int hargslen (host_t * argv []);
host_t ** hargsadd (host_t * argv [], host_t * h);
host_t ** hostsall (interface_t * intf);
char ** hostskeys (interface_t * intf);
int hostnolocal (host_t * hosts []);
int hostnoforeign (host_t * hosts []);
host_t * hostbykey (interface_t * intf, char * key);
host_t * addtohwnames (interface_t * intf, char * key);
host_t * addtoipnames (interface_t * intf, char * key);
host_t * bindtoipnames (interface_t * intf, char * ipaddr, host_t * h);
host_t * bindtohostnames (interface_t * intf, char * hostname, host_t * h);

/* === Containers === */

/* Public functions in file commands.c */
unsigned cmd_size (void);
char ** cmd_names (void);
pksh_cmd_t * cmd_by_name (char * name);
pksh_cmd_t * cmd_lookup (unsigned i);
char * cmd_by_index (unsigned i);
unsigned maxname (void);



/* Public functions in file interface.c */
interface_t * activeintf (void);
interface_t * lastestintf (void);
void setactiveintf (interface_t * current);
void resetactiveintf (interface_t * intf);
char * getintfname (void);
int intflen (interface_t * argv []);
interface_t ** intfadd (interface_t * argv [], char * name, int snapshot, int promiscuous, int timeout, char * filter, pcap_t * pcap, interface_t ** more);
interface_t ** intfsub (interface_t * argv [], char * name);
void intfclean (interface_t * argv []);
interface_t * intfbyname (interface_t * argv [], char * name);
counter_t intfbytes (interface_t * argv []);
counter_t intfpkts (interface_t * argv []);

#if !defined(ROCCO)
/* Public functions in file interval.c */
int _days_ (time_t t1, time_t t2);
int _hours_ (time_t t1, time_t t2);
int _mins_ (time_t t1, time_t t2);
/* time_t samet (struct timeval * t2, struct timeval * t1); */
int days (struct timeval * t2, struct timeval * t1);
int hours (struct timeval * t2, struct timeval * t1);
int mins (struct timeval * t2, struct timeval * t1);
int secs (struct timeval * t2, struct timeval * t1);
time_t msecs (struct timeval * t2, struct timeval * t1);
time_t usecs (struct timeval * t2, struct timeval * t1);
struct timeval * tvnow (void);
char * elapsedtime (struct timeval * start, struct timeval * stop);
#endif /* ROCCO */

/* Public functions in file render.c */
char * percentage (counter_t partial, counter_t total);
char * fmtbytes (counter_t bytes);
char * fmtpkts (counter_t pkts);
int hostlocal (host_t * h);
int hostipless (host_t * h);
int hostunresolved (host_t * h);
void unique_id_printf (host_t * h, char * label);
void firstseen_printf (host_t * h);
void lastseen_printf (host_t * h);
void age_uptime_printf (host_t * h);
void idle_uptime_printf (host_t * h);
void bytes_distribution (host_t * h);
void packets_distribution (host_t * h);
void protocols_distribution (host_t * h);
void tcp_protocols_distribution (host_t * h);
int hostlongest (host_t * argv [], int numeric);
void hostprintf (host_t * h, int argc, char * argv [], char fsep);

/* Public functions in file glob.c */
char ** globargs (int argc, char * argv [], const char * pattern);

/* Public functions in file datalink.c */
int multicast (char * addr);
char * mactoa (u_char * e);
void ethernet (interface_t * intf, struct pcap_pkthdr * h, const u_char * p);
void loopback (interface_t * intf, struct pcap_pkthdr * h, const u_char * p);

/* Public functions in file decoders.c */
void resolvvendorname (host_t * h);
void ip (interface_t * intf, header_t * h, u_char * p, host_t * srchost, host_t * dsthost);
void arp (interface_t * intf, header_t * h, u_char * p, host_t * srchost, host_t * dsthost);
void rarp (interface_t * intf, header_t * h, u_char * p, host_t * srchost, host_t * dsthost);
void icmp (interface_t * intf, header_t * h, u_char * p, host_t * srchost, host_t * dsthost);
void tcp (interface_t * intf, header_t * h, u_char * p, host_t * srchost, host_t * dsthost);
void udp (interface_t * intf, header_t * h, u_char * p, host_t * srchost, host_t * dsthost);
void http (interface_t * intf, header_t * h, u_char * p, host_t * srchost, host_t * dsthost);
void smtp (interface_t * intf, header_t * h, u_char * p, host_t * srchost, host_t * dsthost);

/* Public functions in file sort.c */
int sort_by_hwaddr (const void * _a, const void * _b);
int sort_by_ip (const void * _a, const void * _b);
int sort_by_hostname (const void * _a, const void * _b);
int sort_by_vendor (const void * _a, const void * _b);
int sort_by_system (const void * _a, const void * _b);
int sort_by_domain (const void * _a, const void * _b);

int sort_by_age (const void * _a, const void * _b);
int sort_by_firstseen (const void * _a, const void * _b);
int sort_by_lastseen (const void * _a, const void * _b);

int sort_by_bytes_all (const void * _a, const void * _b);
int sort_by_broadcast_bytes (const void * _a, const void * _b);
int sort_by_multicast_bytes (const void * _a, const void * _b);
int sort_by_ip_bytes_all (const void * _a, const void * _b);
int sort_by_ip_broadcast_bytes (const void * _a, const void * _b);
int sort_by_ip_multicast_bytes (const void * _a, const void * _b);
int sort_by_tcp_bytes_all (const void * _a, const void * _b);
int sort_by_udp_bytes_all (const void * _a, const void * _b);
int sort_by_icmp_bytes_all (const void * _a, const void * _b);
int sort_by_other_ip_bytes_all (const void * _a, const void * _b);

int sort_by_bytes_sent (const void * _a, const void * _b);
int sort_by_ip_bytes_sent (const void * _a, const void * _b);
int sort_by_tcp_bytes_sent (const void * _a, const void * _b);
int sort_by_udp_bytes_sent (const void * _a, const void * _b);
int sort_by_icmp_bytes_sent (const void * _a, const void * _b);
int sort_by_other_ip_bytes_sent (const void * _a, const void * _b);

int sort_by_bytes_recv (const void * _a, const void * _b);
int sort_by_ip_bytes_recv (const void * _a, const void * _b);
int sort_by_tcp_bytes_recv (const void * _a, const void * _b);
int sort_by_udp_bytes_recv (const void * _a, const void * _b);
int sort_by_icmp_bytes_recv (const void * _a, const void * _b);
int sort_by_other_ip_bytes_recv (const void * _a, const void * _b);

int sort_by_current_bytes_all (const void * _a, const void * _b);
int sort_by_average_bytes_all (const void * _a, const void * _b);
int sort_by_peak_bytes_all (const void * _a, const void * _b);

int sort_by_pkts_all (const void * _a, const void * _b);
int sort_by_pkts_sent (const void * _a, const void * _b);
int sort_by_broadcast_pkts (const void * _a, const void * _b);
int sort_by_multicast_pkts (const void * _a, const void * _b);
int sort_by_ip_pkts_all (const void * _a, const void * _b);
int sort_by_ip_broadcast_pkts (const void * _a, const void * _b);
int sort_by_ip_multicast_pkts (const void * _a, const void * _b);
int sort_by_tcp_pkts_all (const void * _a, const void * _b);
int sort_by_udp_pkts_all (const void * _a, const void * _b);
int sort_by_icmp_pkts_all (const void * _a, const void * _b);
int sort_by_other_ip_pkts_all (const void * _a, const void * _b);

int sort_by_pkts_sent (const void * _a, const void * _b);
int sort_by_ip_pkts_sent (const void * _a, const void * _b);
int sort_by_tcp_pkts_sent (const void * _a, const void * _b);
int sort_by_udp_pkts_sent (const void * _a, const void * _b);
int sort_by_icmp_pkts_sent (const void * _a, const void * _b);
int sort_by_other_ip_pkts_sent (const void * _a, const void * _b);

int sort_by_pkts_recv (const void * _a, const void * _b);
int sort_by_ip_pkts_recv (const void * _a, const void * _b);
int sort_by_tcp_pkts_recv (const void * _a, const void * _b);
int sort_by_udp_pkts_recv (const void * _a, const void * _b);
int sort_by_icmp_pkts_recv (const void * _a, const void * _b);
int sort_by_other_ip_pkts_recv (const void * _a, const void * _b);

int sort_by_current_pkts_all (const void * _a, const void * _b);
int sort_by_average_pkts_all (const void * _a, const void * _b);
int sort_by_peak_pkts_all (const void * _a, const void * _b);

int sort_by_ip_bytes_all (const void * _a, const void * _b);
int sort_by_http_bytes_all (const void * _a, const void * _b);
int sort_by_ftp_bytes_all (const void * _a, const void * _b);
int sort_by_dns_bytes_all (const void * _a, const void * _b);
int sort_by_mail_bytes_all (const void * _a, const void * _b);
int sort_by_ssh_bytes_all (const void * _a, const void * _b);
int sort_by_telnet_bytes_all (const void * _a, const void * _b);
int sort_by_netbios_ip_bytes_all (const void * _a, const void * _b);
int sort_by_other_ip_bytes_all (const void * _a, const void * _b);

/* Public functions in file vendor.c */
void vtfill (void);
char * vendor (char * mac);

/* Public functions in file ettercap.c */
void osfingerprintfill (void);
char * osfingerprintmatch (char * fp);


/* Public functions in file tcsh-wrap.c */
unsigned tcsh_screen_rows (void);
unsigned tcsh_screen_cols (void);
void tcsh_set_variable (char * name, char * value);
void tcsh_unset_variable (char * var);
void tcsh_builtins (int argc, char * argv []);

/* Public functions in file init.c */
void pksh_init (char * progname, int quiet);

/* Public functions in file prompt.c */
void pksh_prompt (char * interface);


/* === Helpers === */

#if !defined(ROCCO)
/* Public functions in file pkhelp.c */
int pksh_pkhelp (int argc, char * argv []);
#endif /* ROCCO */

/* Public functions in file help.c */
int pksh_exit (int argc, char * argv []);
int pksh_quit (int argc, char * argv []);
int pksh_help (int argc, char * argv []);

/* Public functions in file about.c */
int pksh_about (int argc, char * argv []);

/* Public functions in file version.c */
int pksh_version (int argc, char * argv []);

/* Public functions in file license.c */
int pksh_license (int argc, char * argv []);

/* Public functions in file when.c */
int pksh_when (int argc, char * argv []);


/* === Network Interfaces === */

/* Public functions in file pkdev.c */
int pksh_pkdev (int argc, char * argv []);

/* Public functions in file open.c */
int pksh_pkopen (int argc, char * argv []);

/* Public functions in file close.c */
int pksh_pkclose (int argc, char * argv []);

/* Public functions in file enable.c */
int pksh_pkenable (int argc, char * argv []);

/* Public functions in file status.c */
int pksh_pkstatus (int argc, char * argv []);

/* Public functions in file uptime.c */
int pksh_pkuptime (int argc, char * argv []);

/* Public functions in file filter.c */
int pksh_pkfilter (int argc, char * argv []);

/* Public functions in file swap.c */
int pksh_pkswap (int argc, char * argv []);


/* === Viewers === */

/* Public functions in file packets.c */
int pksh_packets (int argc, char * argv []);

/* Public functions in file bytes.c */
int pksh_bytes (int argc, char * argv []);

/* Public functions in file hosts.c */
int pksh_pkhosts (int argc, char * argv []);

/* Public functions in file arp.c */
int pksh_pkarp (int argc, char * argv []);

/* Public functions in file finger.c */
int pksh_pkfinger (int argc, char * argv []);

/* Public functions in file last.c */
int pksh_pklast (int argc, char * argv []);

/* Public functions in file who.c */
int pksh_pkwho (int argc, char * argv []);

/* Public functions in file protocols.c */
int pksh_protocols (int argc, char * argv []);

/* Public functions in file services.c */
int pksh_services (int argc, char * argv []);

/* Public functions in file throughput.c */
int pksh_throughput (int argc, char * argv []);


/*
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
 * Do not edit anything below, configure creates it.
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
 */

/* Definitions for builtin extensions to the shell will be automatically inserted here by the configure script */

