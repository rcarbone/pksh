/*
 * pksh - The Packet Shell
 *
 * R. Carbone (rocco@tecsiel.it)
 * 2008-2009, 2022
 *
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * How to handle the table of network interface(s)
 */


/* System headers */
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

/* Project header */
#include "pksh.h"


/* The table of network interfaces */
interface_t ** interfaces = NULL;

/* The stack of most referenced interfaces (the current and the previous) */
interface_t * active   = NULL;
interface_t * previous = NULL;


/* Return the hardware address for 'interface' */
static struct sockaddr * hwaddress (char * interface)
{
  static struct ifreq req;

  int fd;

  /* Open a socket to query for network configuration parameters */
  fd = socket (AF_INET, SOCK_DGRAM, 0);
  if (fd == -1)
    return NULL;

  /* All interface ioctl's must have parameter definitions begining with ifr_name */
  memset (& req, 0, sizeof (req));
  strncpy (req . ifr_name, interface, sizeof (req . ifr_name));
  req . ifr_addr . sa_family = AF_INET;

  /* Retrieve hardware address for this interface */
  if (ioctl (fd, SIOCGIFHWADDR, & req) == -1)
    {
      close (fd);
      return NULL;
    }

  close (fd);

  return (struct sockaddr *) & req . ifr_hwaddr;
}


/* Return the Internet address for 'interface' */
static struct sockaddr_in * ipaddress (char * interface)
{
  static struct ifreq req;

  int fd;

  /* Open a socket to query for network configuration parameters */
  if ((fd = socket (AF_INET, SOCK_DGRAM, 0)) == -1)
    return NULL;

  /* All interface ioctl's must have parameter definitions begining with ifr_name */
  memset (& req, 0, sizeof (req));
  strncpy (req . ifr_name, interface, sizeof (req . ifr_name));
  req . ifr_addr . sa_family = AF_INET;

  /* Retrieve Internet address for this interface */
  if (ioctl (fd, SIOCGIFADDR, & req) == -1)
    {
      close (fd);
      return NULL;
    }

  close (fd);

  return (struct sockaddr_in *) & req . ifr_addr;
}


/* Return the Internet netwotk mask for 'interface' */
static struct sockaddr_in * netmaskaddr (char * interface)
{
  static struct ifreq req;

  int fd;

  /* Open a socket to query for network configuration parameters */
  fd = socket (AF_INET, SOCK_DGRAM, 0);
  if (fd == -1)
    return NULL;

  /* All interface ioctl's must have parameter definitions begining with ifr_name */
  memset (& req, 0, sizeof (req));
  strncpy (req . ifr_name, interface, sizeof (req . ifr_name));
  req . ifr_addr . sa_family = AF_INET;

  /* Retrieve Internet network mask for this interface */
  if (ioctl (fd, SIOCGIFNETMASK, & req) == -1)
    {
      close (fd);
      return NULL;
    }

  close (fd);

  return (struct sockaddr_in *) & req . ifr_netmask;
}


/* Return the broadcast address for 'interface' */
static struct sockaddr_in * broadcastaddr (char * interface)
{
  static struct ifreq req;

  int fd;

  /* Open a socket to query for network configuration parameters */
  if ((fd = socket (AF_INET, SOCK_DGRAM, 0)) == -1)
    return NULL;

  /* All interface ioctl's must have parameter definitions begining with ifr_name */
  memset (& req, 0, sizeof (req));
  strncpy (req . ifr_name, interface, sizeof (req . ifr_name));
  req . ifr_addr . sa_family = AF_INET;

  /* Retrieve Broadcast address for this interface */
  if (ioctl (fd, SIOCGIFBRDADDR, & req) == -1)
    {
      close (fd);
      return NULL;
    }

  close (fd);

  return (struct sockaddr_in *) & req . ifr_broadaddr;
}


/* Return the MTU for 'interface' */
static int mtu (char * interface)
{
  static struct ifreq req;

  int fd;

  /* Open a socket to query for network configuration parameters */
  if ((fd = socket (AF_INET, SOCK_DGRAM, 0)) == -1)
    return -1;

  /* All interface ioctl's must have parameter definitions begining with ifr_name */
  memset (& req, 0, sizeof (req));
  strncpy (req . ifr_name, interface, sizeof (req . ifr_name));
  req . ifr_addr . sa_family = AF_INET;

  /* Retrieve hardware address for this interface */
  if (ioctl (fd, SIOCGIFMTU, & req) == -1)
    {
      close (fd);
      return -1;
    }

  close (fd);

  return req . ifr_mtu;
}


/* Return the current referenced interface */
interface_t * activeintf (void)
{
  return active;
}


/* Return the latest referenced interface */
interface_t * lastestintf (void)
{
  return previous;
}


/* Set 'intf' as the active interface */
void setactiveintf (interface_t * intf)
{
  previous = active;
  active = intf;
}


/* Reset the active interface after 'intf' has been closed */
void resetactiveintf (interface_t * intf)
{
  if (intf == active)
    active = previous,
      previous = NULL;
  else if (intf == previous)
    previous = NULL;
}


/* Retrieve the name of the active interface (if any) */
char * getintfname (void)
{
  return active ? active -> name : NULL;
}


/* Return the number of interfaces in the table */
int intflen (interface_t * argv [])
{
  int argc = 0; while (argv && * argv ++) argc ++; return argc;
}


/* Allocate and initialize a new interface descriptor */
static interface_t * mkintf (char * name, int snapshot, int promiscuous, int timeout, char * filter, pcap_t * pcap)
{
  struct sockaddr * hwaddr       = hwaddress (name);     /* returned by the OS via ioctl() */
  struct sockaddr_in * ipaddr    = ipaddress (name);     /* returned by the OS via ioctl() */
  struct sockaddr_in * netmask   = netmaskaddr (name);   /* returned by the OS via ioctl() */

  struct hostent * hostname      = NULL;
  struct in_addr network;
  struct sockaddr_in * broadcast = broadcastaddr (name);
  char buf [PCAP_ERRBUF_SIZE];

  /* Buy memory now */
  interface_t * intf = calloc (sizeof (interface_t), 1);
  if (! intf)
    return NULL;

  /* Identifiers and status */
  intf -> name        = strdup (name);
  intf -> status      = pcap ? INTERFACE_READY : INTERFACE_DOWN;

  intf -> snapshot    = snapshot;
  intf -> promiscuous = promiscuous;
  intf -> timeout     = timeout;
  intf -> maxcount    = 0;
  intf -> filter      = filter ? strdup (filter) : NULL;
  intf -> pcap        = pcap;

  /* Attempt to get the interface network number and its mask (just for pcap_compile(), otherwise I could also live without) */
  pcap_lookupnet (name, & intf -> pcapnetwork, & intf -> pcapnetmask, buf);

  /* Interface identifiers for fast host addresses computation */
  intf -> ipbin        = ipaddr ? ipaddr -> sin_addr . s_addr : 0;
  intf -> netmaskbin   = netmask ? netmask -> sin_addr . s_addr : 0;
  intf -> networkbin   = intf -> ipbin & intf -> netmaskbin;
  intf -> broadcastbin = intf -> ipbin | ~ intf -> netmaskbin;

  /* Determine the type of the underlying network and the data-link encapsulation method
   * Warning:
   *   libpcap version 0.9.8 seems to have problems with loopback interface on linux
   *   because the pcap_datalink() returns DLT_EN10MB instead of DLT_NULL,
   *   so I need to recover from this problem.
   *
   * rocco@tar 7584> sudo ./test-pcap -i lo
   * test-pcap: Ready, now listening from lo using libpcap version 0.9.8
   * test-pcap: interface 'lo' data-link type => 1 [Ethernet - EN10MB]
   */
  intf -> datalink    = intf -> ipaddr && ! strcmp (intf -> ipaddr, LOOPBACK_ADDR) ? DLT_NULL : pcap_datalink (pcap);

  /* Interface identifiers for humans */
  intf -> hwaddr      = hwaddr && intf -> datalink == DLT_EN10MB ? strdup (mactoa ((u_char *) hwaddr -> sa_data)) : NULL;
  if (ipaddr)
    {
      intf -> ipaddr  = strdup (inet_ntoa (ipaddr -> sin_addr));
      if ((hostname   = gethostbyaddr ((char *) & ipaddr -> sin_addr, sizeof (ipaddr -> sin_addr), AF_INET)))
	intf -> hostname = strdup (hostname -> h_name);
    }

  network . s_addr    = intf -> pcapnetwork;

  intf -> network     = strdup (inet_ntoa (network));
  intf -> netmask     = netmask ? strdup (inet_ntoa (netmask -> sin_addr)) : NULL;
  intf -> broadcast   = broadcast ? strdup (inet_ntoa (broadcast -> sin_addr)) : NULL;
  intf -> mtu         = mtu (name);

  intf -> shortest  = intf -> mtu;   /* temporary initialization until first packet has arrived */

  gettimeofday (& intf -> started, NULL);

  return intf;
}


/* Free allocated memory and resources used to store an interface */
static void rmintf (interface_t * intf)
{
  if (! intf)
    return;

  if (intf -> name)
    free (intf -> name);

  if (intf -> filter)
    free (intf -> filter);

  if (intf -> ipaddr)
    free (intf -> ipaddr);
  if (intf -> hostname)
    free (intf -> hostname);

  free (intf);
}


/* Return the index of an interface into the table of currently active interfaces */
static int posintf (interface_t * argv [], char * name)
{
  int i = -1;

  while (name && argv && * argv)
    if (! strcmp ((* argv ++) -> name, name))
      return i + 1;
    else
      i ++;

  return -1;
}


/* Add an interface to a table of currently active interfaces */
interface_t ** intfadd (interface_t * argv [], char * name, int snapshot, int promiscuous,
			int timeout, char * filter, pcap_t * pcap, interface_t ** more)
{
  int argc;
  interface_t * intf;

  if ((intf = mkintf (name, snapshot, promiscuous, timeout, filter, pcap)))
    {
      argc = intflen (argv);
      argv = (interface_t **) realloc (argv, (1 + argc + 1) * sizeof (interface_t **));
      if (! argv)
        {
          rmintf (intf);
          return NULL;
        }
      argv [argc ++] = intf;
      argv [argc] = NULL;         /* do the table NULL terminated */

      if (more)
	* more = intf;
    }
  return argv;
}


/* Remove an interface from the table of currently active interfaces */
interface_t ** intfsub (interface_t * argv [], char * name)
{
  int i;
  int j;
  int argc;

  if ((i = posintf (argv, name)) != -1)
    {
      argc = intflen (argv);
      rmintf (argv [i]);                  /* free the descriptor */
      for (j = i; j < argc - 1; j ++)     /* move pointers back one position */
        argv [j] = argv [j + 1];

      argv [j] = NULL;                    /* terminate the table */

      if (argc > 1)
        argv = (interface_t **) realloc (argv, argc * sizeof (interface_t *));
      else
        free (argv), argv = NULL;
    }

  return argv;
}


/* Free the table in the NULL terminated table 'argv' */
void intfclean (interface_t * argv [])
{
  interface_t ** s = argv;

  while (s && * s)
    rmintf (* s ++);
  if (argv)
    free (argv);
}


/* Lookup for an item in the NULL terminated table 'argv' */
interface_t * intfbyname (interface_t * argv [], char * name)
{
  while (name && argv && * argv)
    if (! strcmp (name, (* argv ++) -> name))
      return * -- argv;
  return NULL;
}


/* Return total # of bytes over all the network interfaces */
counter_t intfbytes (interface_t * argv [])
{
  counter_t bytes = 0;
  while (argv && * argv)
    bytes += (* argv ++) -> bytes_total;
  return bytes;
}


/* Return total # of packets over all the network interfaces */
counter_t intfpkts (interface_t * argv [])
{
  counter_t pkts = 0;
  while (argv && * argv)
    pkts += (* argv ++) -> pkts_total;
  return pkts;
}
