/*
 * pksh - The Packet Shell
 *
 * R. Carbone (rocco@tecsiel.it)
 * 2003, 2008-2009, 2022
 *
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Display detailed about the current status of network interface(s)
 */


/* System headers */
#include <time.h>

/* Project header */
#include "pksh.h"

/* Identifiers */
#define NAME         "pkstatus"
#define BRIEF        "Display detailed about the current status of network interface(s)"
#define SYNOPSIS     "pkstatus [options]"
#define DESCRIPTION  "No description yet"

/* Public variable */
pksh_cmd_t cmd_status = { NAME, BRIEF, SYNOPSIS, DESCRIPTION, pksh_pkstatus };


/* GNU short options */
enum
{
  /* Startup */
  OPT_HELP        = 'h',
  OPT_QUIET       = 'q',
};


/* GNU long options */
static struct option lopts [] =
{
  /* Startup */
  { "help",          no_argument,       NULL, OPT_HELP        },
  { "quiet",         no_argument,       NULL, OPT_QUIET       },

  { NULL,            0,                 NULL, 0               }
};


/* Display the syntax */
static void usage (char * progname, struct option * options)
{
  printf ("`%s' prints current network interface information in a format readable for humans\n", progname);

  printf ("\n");
  printf ("Usage: %s [options] [interface]\n", progname);

  printf ("\n");
  printf ("Examples:\n");
  printf ("   %s           # print details about the active interface (if any)\n", progname);
  printf ("   %s eth1      # show information about interface eth1\n", progname);

  printf ("\n");
  printf ("Main options are:\n");
  printf ("   -h, --help           only show this help message\n");
}


/* Print current network interface information in a format readable for humans */
int pksh_pkstatus (int argc, char * argv [])
{
  char * progname = basename (argv [0]);
  char * sopts    = optlegitimate (lopts);

  /* Variables that are set according to the specified options */
  bool quiet      = false;

  int option;

  /* Local variables */
  char * name = NULL;
  interface_t * interface;

  struct pcap_stat stats;

  struct timeval * now = tvnow ();

  /* Lookup for the command in the static table of registered extensions */
  if (! cmd_by_name (progname))
    {
      printf ("%s: Command [%s] not found.\n", progname, progname);
      return -1;
    }

  /* Parse command line options */
  optind = 0;
  optarg = NULL;
  argv [0] = progname;
  while ((option = getopt_long (argc, argv, sopts, lopts, NULL)) != -1)
    {
      switch (option)
	{
	default: if (! quiet) printf ("Try '%s --help' for more information.\n", progname); return 1;

	  /* Startup */
	case OPT_HELP:  usage (progname, lopts); return 0;
	case OPT_QUIET: quiet = true;            break;
	}
    }

  /* Check if the user has specified an interface */
  if (optind < argc)
    name = argv [optind ++];

  /* Safe to play with the 'active' interface (if any) in case no specific one was chosen by the user */
  if (! name && ! (name = getintfname ()))
    {
      printf ("%s: no interface is currently enabled for packet sniffing\n", argv [0]);
      return -1;
    }

  /* Lookup for the given name in the table of enabled interfaces */
  if (! (interface = intfbyname (interfaces, name)))
    {
      printf ("%s: unknown interface %s\n", argv [0], name);
      return -1;
    }

  /* Get packet statistics from the start of the run to current time */
  pcap_stats (interface -> pcap, & stats);

  /* Give general information about the interface */
  printf ("Network interface    : %s [%s - %s] [%s] [mtu %d] set to %s mode\n",
	  name, pcap_datalink_val_to_description (interface -> datalink), pcap_datalink_val_to_name (interface -> datalink),
	  interface -> hwaddr ? interface -> hwaddr : "", interface -> mtu, interface -> promiscuous ? "promiscuous" : "non promiscuous");

  if (interface -> hostname && interface -> ipaddr)
    printf ("Address              : %s [%s]\n", interface -> hostname, interface -> ipaddr);
  if (interface -> network && interface -> netmask && interface -> broadcast)
    printf ("Internet             : network [%s] netmask [%s] broadast [%s]\n",
	    interface -> network, interface -> netmask, interface -> broadcast);

  printf ("Sampling since       : %s [%*.*s]", elapsedtime (& interface -> started, now), 24, 24, ctime (& interface -> started . tv_sec));
  printf ("\n\n");

  printf ("Packets:\n");

  if (stats . ps_recv != interface -> pkts_total)
    {
      if (interface -> datalink == DLT_NULL)
	printf ("  Received by kernel : %s\n", fmtpkts (stats . ps_recv));
      else
	printf ("  Received by kernel : %s\n", fmtpkts (stats . ps_recv));
    }

  if (stats . ps_drop)
    printf ("  Dropped by kernel  : %s\n", fmtpkts (stats . ps_drop));
  if (stats . ps_recv != stats . ps_drop + interface -> pkts_total)
    printf ("  Still enqueued     : %s\n",
	    stats . ps_recv > stats . ps_drop + interface -> pkts_total ?
	    fmtpkts (stats . ps_recv - stats . ps_drop - interface -> pkts_total) :
	    fmtpkts (stats . ps_drop + interface -> pkts_total - stats . ps_recv));

  if (interface -> datalink == DLT_NULL)
    {
      if (stats . ps_recv / 2 == interface -> pkts_total)
	printf ("  Total counted      : %s %s\n", fmtpkts (interface -> pkts_total),
		intflen (interfaces) > 1 ? percentage (interface -> pkts_total, intfpkts (interfaces)) : "");
      else
	printf ("  Total counted      : %s %s\n", fmtpkts (interface -> pkts_total),
		intflen (interfaces) > 1 ? percentage (interface -> pkts_total, intfpkts (interfaces)) : "");
    }
  else
    {
      if (stats . ps_recv == interface -> pkts_total)
	printf ("  Total counted      : %s %s\n", fmtpkts (interface -> pkts_total),
		intflen (interfaces) > 1 ? percentage (interface -> pkts_total, intfpkts (interfaces)) : "");
      else
	printf ("  Total counted      : %s %s\n", fmtpkts (interface -> pkts_total),
		intflen (interfaces) > 1 ? percentage (interface -> pkts_total, intfpkts (interfaces)) : "");
    }

  /* Packets distribution */
  if (interface -> pkts_total)
    {
      /* Packets size in bytes and packet distribution */
      printf ("\n");
      printf ("  Packet Size        : %d/%lu/%d [Min/Avg/Max]\n",
	      interface -> shortest, interface -> bytes_total / interface -> pkts_total, interface -> longest);

      printf ("  Packet ranges      :\n");
      printf ("      Upto75         : %s %s\n", fmtpkts (interface -> upto75),   percentage (interface -> upto75,   interface -> pkts_total));
      printf ("      Upto150        : %s %s\n", fmtpkts (interface -> upto150),  percentage (interface -> upto150,  interface -> pkts_total));
      printf ("      Upto225        : %s %s\n", fmtpkts (interface -> upto225),  percentage (interface -> upto225,  interface -> pkts_total));
      printf ("      Upto300        : %s %s\n", fmtpkts (interface -> upto300),  percentage (interface -> upto300,  interface -> pkts_total));
      printf ("      Upto375        : %s %s\n", fmtpkts (interface -> upto375),  percentage (interface -> upto375,  interface -> pkts_total));
      printf ("      Upto450        : %s %s\n", fmtpkts (interface -> upto450),  percentage (interface -> upto450,  interface -> pkts_total));
      printf ("      Upto525        : %s %s\n", fmtpkts (interface -> upto525),  percentage (interface -> upto525,  interface -> pkts_total));
      printf ("      Upto600        : %s %s\n", fmtpkts (interface -> upto600),  percentage (interface -> upto600,  interface -> pkts_total));
      printf ("      Upto675        : %s %s\n", fmtpkts (interface -> upto675),  percentage (interface -> upto675,  interface -> pkts_total));
      printf ("      Upto750        : %s %s\n", fmtpkts (interface -> upto750),  percentage (interface -> upto750,  interface -> pkts_total));
      printf ("      Upto825        : %s %s\n", fmtpkts (interface -> upto825),  percentage (interface -> upto825,  interface -> pkts_total));
      printf ("      Upto900        : %s %s\n", fmtpkts (interface -> upto900),  percentage (interface -> upto900,  interface -> pkts_total));
      printf ("      Upto975        : %s %s\n", fmtpkts (interface -> upto975),  percentage (interface -> upto975,  interface -> pkts_total));
      printf ("      Upto1050       : %s %s\n", fmtpkts (interface -> upto1050), percentage (interface -> upto1050, interface -> pkts_total));
      printf ("      Upto1125       : %s %s\n", fmtpkts (interface -> upto1125), percentage (interface -> upto1125, interface -> pkts_total));
      printf ("      Upto1200       : %s %s\n", fmtpkts (interface -> upto1200), percentage (interface -> upto1200, interface -> pkts_total));
      printf ("      Upto1275       : %s %s\n", fmtpkts (interface -> upto1275), percentage (interface -> upto1275, interface -> pkts_total));
      printf ("      Upto1350       : %s %s\n", fmtpkts (interface -> upto1350), percentage (interface -> upto1350, interface -> pkts_total));
      printf ("      Upto1425       : %s %s\n", fmtpkts (interface -> upto1425), percentage (interface -> upto1425, interface -> pkts_total));
      printf ("      Upto1514       : %s %s\n", fmtpkts (interface -> upto1514), percentage (interface -> upto1514, interface -> pkts_total));

      printf ("      Above1514      : %s %s\n", fmtpkts (interface -> above1514), percentage (interface -> above1514, interface -> pkts_total));
      printf ("\n");

      printf ("    Unicast          : %s %s\n",
	      fmtpkts (interface -> pkts_total - interface -> pkts_broadcast - interface -> pkts_multicast),
	      percentage (interface -> pkts_total - interface -> pkts_broadcast - interface -> pkts_multicast, interface -> pkts_total));

      if (interface -> pkts_broadcast)
	printf ("    Broadcast        : %s %s\n", fmtpkts (interface -> pkts_broadcast),
		percentage (interface -> pkts_broadcast, interface -> pkts_total));
      if (interface -> pkts_multicast)
	printf ("    Multicast        : %s %s\n", fmtpkts (interface -> pkts_multicast),
		percentage (interface -> pkts_multicast, interface -> pkts_total));
      printf ("\n");

      if (interface -> pkts_ip)
	printf ("    IP               : %s %s\n", fmtpkts (interface -> pkts_ip),
		percentage (interface -> pkts_ip, interface -> pkts_total));

      if (interface -> pkts_tcp)
	printf ("      TCP            : %s %s\n", fmtpkts (interface -> pkts_tcp),
		percentage (interface -> pkts_tcp, interface -> pkts_ip));
      if (interface -> pkts_udp)
	printf ("      UDP            : %s %s\n", fmtpkts (interface -> pkts_udp),
		percentage (interface -> pkts_udp, interface -> pkts_ip));
      if (interface -> pkts_icmp)
	printf ("      ICMP           : %s %s\n", fmtpkts (interface -> pkts_icmp),
		percentage (interface -> pkts_icmp, interface -> pkts_ip));
      if (interface -> pkts_other_ip)
	printf ("      Other IP       : %s %s\n", fmtpkts (interface -> pkts_other_ip),
		percentage (interface -> pkts_other_ip, interface -> pkts_ip));

      if (interface -> pkts_arp)
	printf ("    ARP              : %s %s\n", fmtpkts (interface -> pkts_arp),
		percentage (interface -> pkts_arp, interface -> pkts_total));
      if (interface -> pkts_rarp)
	printf ("    RARP             : %s %s\n", fmtpkts (interface -> pkts_rarp),
		percentage (interface -> pkts_rarp, interface -> pkts_total));
      if (interface -> pkts_non_ip)
	printf ("    Non-IP           : %s %s\n", fmtpkts (interface -> pkts_non_ip),
		percentage (interface -> pkts_non_ip, interface -> pkts_total));
    }
  printf ("\n");

  printf ("Bytes:\n");
  printf ("  Total counted      : %s %s\n", fmtbytes (interface -> bytes_total),
	  intflen (interfaces) > 1 ? percentage (interface -> bytes_total, intfbytes (interfaces)) : "");

  /* Bytes distribution */
  if (interface -> bytes_total)
    {
      if (interface -> bytes_ip)
	printf ("    IP               : %s %s\n", fmtbytes (interface -> bytes_ip),
		percentage (interface -> bytes_ip, interface -> bytes_total - interface -> headers_total));

      if (interface -> bytes_tcp)
	printf ("      TCP            : %s %s\n", fmtbytes (interface -> bytes_tcp),
		percentage (interface -> bytes_tcp, interface -> bytes_ip - interface -> headers_ip));
      if (interface -> bytes_udp)
	printf ("      UDP            : %s %s\n", fmtbytes (interface -> bytes_udp),
		percentage (interface -> bytes_udp, interface -> bytes_ip - interface -> headers_ip));
      if (interface -> bytes_icmp)
	printf ("      ICMP           : %s %s\n", fmtbytes (interface -> bytes_icmp),
		percentage (interface -> bytes_icmp, interface -> bytes_ip - interface -> headers_ip));
      if (interface -> bytes_other_ip)
	printf ("      Other IP       : %s %s\n", fmtbytes (interface -> bytes_other_ip),
		percentage (interface -> bytes_other_ip, interface -> bytes_ip - interface -> headers_ip));

      if (interface -> bytes_arp)
	printf ("    ARP              : %s %s\n", fmtbytes (interface -> bytes_arp),
		percentage (interface -> bytes_arp, interface -> bytes_total - interface -> headers_total));
      if (interface -> bytes_rarp)
	printf ("    RARP             : %s %s\n", fmtbytes (interface -> bytes_rarp),
		percentage (interface -> bytes_rarp, interface -> bytes_total - interface -> headers_total));
      if (interface -> bytes_non_ip)
	printf ("    Non-IP           : %s %s\n", fmtbytes (interface -> bytes_non_ip),
		percentage (interface -> bytes_non_ip, interface -> bytes_total - interface -> headers_total));

#if defined(FIXME)
      printf ("      NetBIOS      : %s\n", fmtbytes (interface -> ));
      printf ("      EGP          : %s\n", fmtbytes (interface -> ));
      printf ("      IPv6         : %s\n", fmtbytes (interface -> ));
      printf ("      AppleTalk    : %s\n", fmtbytes (interface -> ));
      printf ("      DecNET       : %s\n", fmtbytes (interface -> ));
      printf ("      DLC          : %s\n", fmtbytes (interface -> ));
      printf ("      IPX          : %s\n", fmtbytes (interface -> ));
      printf ("      OSI          : %s\n", fmtbytes (interface -> ));
#endif /* FIXME */
    }

  printf ("\n");

  /* Bye bye! */
  return 0;
}
