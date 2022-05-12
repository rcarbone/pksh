/*
 * pksh - The Packet Shell
 *
 * R. Carbone (rocco@tecsiel.it)
 * 2008-2009, 2022
 *
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 */


/* Avoid warning: 'pcap_lookupdev' is deprecated: use 'pcap_findalldevs' and use the first device [-Wimplicit-function-declaration] */
#if defined(__GNUC__)
#pragma GCC diagnostic ignored   "-Wimplicit-function-declaration"
#pragma GCC diagnostic ignored   "-Wdeprecated-declarations"
#else /* defined(__clang__) */
#pragma clang diagnostic ignored "-Wimplicit-function-declaration"
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#endif


/* System headers */
#include <stdlib.h>
#include <unistd.h>

/* Project header */
#include "pksh.h"


/* Identifiers */
#define NAME         "pkenable"
#define BRIEF        "Enable packets capture on network interface(s)"
#define SYNOPSIS     "pkenable [options]"
#define DESCRIPTION  "No description yet"

/* Public variable */
pksh_cmd_t cmd_enable = { NAME, BRIEF, SYNOPSIS, DESCRIPTION, pksh_pkenable };

/* GNU short options */
enum
{
  /* Startup */
  OPT_HELP        = 'h',
  OPT_QUIET       = 'q',

  OPT_SNAPSHOT    = 's',
  OPT_PROMISCUOUS = 'p',
  OPT_TIMEOUT     = 't',
  OPT_MAXCOUNT    = 'c',
};


/* GNU long options */
static struct option lopts [] =
{
  /* Startup */
  { "help",          no_argument,       NULL, OPT_HELP        },
  { "quiet",         no_argument,       NULL, OPT_QUIET       },

  { "snapshot",      required_argument, NULL, OPT_SNAPSHOT    },
  { "promiscuous",   no_argument,       NULL, OPT_PROMISCUOUS },
  { "timeout",       required_argument, NULL, OPT_TIMEOUT     },
  { "maxcount",      required_argument, NULL, OPT_MAXCOUNT    },

  { "hardware-size", required_argument, NULL, 128             },
  { "ip-size",       required_argument, NULL, 129             },
  { "hostname-size", required_argument, NULL, 130             },

  { "hw",            required_argument, NULL, 128             },
  { "ip",            required_argument, NULL, 129             },
  { "ht",            required_argument, NULL, 130             },

  { NULL,            0,                 NULL, 0               }
};


/* Define a network interface data-link with its parser/counter function */
typedef struct
{
  int type;          /* data-link type as returned by pcap_datalink() */
  void (* counter) (interface_t * intf, struct pcap_pkthdr * h, const u_char * p);

} datalink_t;


/* The table of known network interface data-links */
static datalink_t datalinks [] =
{
  { DLT_NULL,       loopback   },   /* BSD loopback encapsulation     */
  { DLT_EN10MB,     ethernet   },   /* Ethernet (10Mb)                */

#if defined(FIXME)
  { DLT_ANY,        anylinux,  },   /* Linux 'any' device             */
  { DLT_IEEE802,    tokenring  },   /* 802.5 Token Ring               */
  { DLT_SLIP,       slip       },   /* Serial Line IP                 */
  { DLT_PPP,        ppp        },   /* Point-to-point Protocol        */
  { DLT_FDDI,       fddi       },   /* FDDI                           */

  { DLT_SLIP_BSDOS, bsdslip    },   /* BSD/OS Serial Line IP          */
  { DLT_SLIP_BSDOS, bsdppp     },   /* BSD/OS Point-to-point Protocol */

  { DLT_C_HDLC,     chdlc      },   /* Cisco HDLC                     */
  { DLT_RAW,        rawip      },   /* Raw IP                         */
  { DLT_IEEE802_11, wireless   },   /* IEEE 802.11 wireless           */
  { DLT_FRELAY,     framerelay },   /* Frame Relay                    */
#endif /* FIXME */

  { -1,             NULL       }
};


/* Check if a parser exist for the given data-link type (linear search) */
static datalink_t * knowndatalink (int type)
{
  datalink_t * d;

  for (d = datalinks; d -> counter; d ++)
    if (d -> type == type)
      return d;
  return NULL;
}


/* Update the packets distribution by size */
static void packets_by_size (int size, interface_t * interface)
{
  interface -> shortest = MIN (interface -> shortest, size);
  interface -> longest  = MAX (interface -> longest, size);

  if (size <= 75)        interface -> upto75 ++;
  else if (size <= 150)  interface -> upto150 ++;
  else if (size <= 225)  interface -> upto225 ++;
  else if (size <= 300)  interface -> upto300 ++;
  else if (size <= 375)  interface -> upto375 ++;
  else if (size <= 450)  interface -> upto450 ++;
  else if (size <= 525)  interface -> upto525 ++;
  else if (size <= 600)  interface -> upto600 ++;
  else if (size <= 675)  interface -> upto675 ++;
  else if (size <= 750)  interface -> upto750 ++;
  else if (size <= 825)  interface -> upto825 ++;
  else if (size <= 900)  interface -> upto900 ++;
  else if (size <= 975)  interface -> upto975 ++;
  else if (size <= 1050) interface -> upto1050 ++;
  else if (size <= 1125) interface -> upto1125 ++;
  else if (size <= 1200) interface -> upto1200 ++;
  else if (size <= 1275) interface -> upto1275 ++;
  else if (size <= 1350) interface -> upto1350 ++;
  else if (size <= 1425) interface -> upto1425 ++;
  else if (size <= 1514) interface -> upto1514 ++;
  else                   interface -> above1514 ++;
}


/*
 * This is the main function of the Packet Shell:
 * continuously capture packets from the network interface(s),
 * analyze and collect them to update the lot of information
 * internally maintained
 */
static void * sniffer (void * _interface)
{
  interface_t * interface = _interface;
  struct pcap_pkthdr header;
  const u_char * packet;

  signal (SIGINT, SIG_IGN);

  while (interface -> status == INTERFACE_ENABLED && (! interface -> maxcount || interface -> pkts_total < interface -> maxcount))
    {
      if ((packet = pcap_next (interface -> pcap, & header)))
	{
	  datalink_t * d;

	  /* Update packets distribution by size */
	  packets_by_size (header . len, interface);

	  /* Attempt to decode and count packets based on the type of data-link */
	  if ((d = knowndatalink (interface -> datalink)))
	    d -> counter (interface, & header, packet);
	  else
	    {
	      interface -> bytes_total += header . len;
	      interface -> pkts_total ++;
	      interface -> bytes_other += header . len;
	      interface -> pkts_other ++;
	    }
	}
    }

  /* Allow next run */
  interface -> status = INTERFACE_READY;
  return NULL;
}


/* Display the syntax */
static void usage (char * progname, struct option * options)
{
  printf ("`%s' starts capturing and processing packets from one (or more) network interface(s).\n", progname);
  printf ("More than one interface may be specified in a comma separated list.\n");
  printf ("On Linux systems with kernels 2.2 or later, an argument of 'any' can be used to capture packets from all available interfaces.\n");
  printf ("Please refer to the pcap (Packet Capture) library for more info about filter expressions ('man pcap').\n");
  printf ("See also documentation of other networking applications if you are in trouble with the meaning of filtering network traffic\n");
  printf ("(e.g. tcpdump, wireshark, snort)\n");

  printf ("\n");
  printf ("Usage: %s [options] [interface[,interface] [ expression ]]\n", progname);

  printf ("\n");
  printf ("Examples:\n");
  printf ("   %s                         # find the first available interface, open it and start processing packets\n", progname);
  printf ("   %s eth1                    # open interface eth1 and start processing packets\n", progname);
  printf ("   %s eth2,eth0,eth1          # start processing packets on interfaces eth2, eth0 and eth1 in this order. Latest is the 'active'\n", progname);
  printf ("   %s hme0 host tecsiel.it    # open interface hme0 to look at packets only for host tecsiel.it\n", progname);

  printf ("\n");
  printf ("Main options are:\n");
  printf ("   -h, --help                         only show this help message\n");
  printf ("   -s, --snapshot                     specify the maximum number of bytes to capture (default %d)\n", DEFAULT_SNAPSHOT);
  printf ("   -p, --promiscuous                  disable promiscuous mode of operation\n");
  printf ("   -t, --timeout                      specify the read timeout in ms (default %d)\n", DEFAULT_TIMEOUT);
  printf ("   -c, --maxcount                     capture maxcount packets and then stop (but interface is left open)\n");

  printf ("  --hw, --hardware-size               specify hash table size for hardware identifiers (default %d)\n", DEFAULT_HW_SIZE);
  printf ("  --ip, --ip-size                     specify hash table size for IP address (default %d)\n", DEFAULT_IP_SIZE);
  printf ("  --ht, --hostname-size               specify hash table size for hostnames (default %d)\n", DEFAULT_HOST_SIZE);
}


/* Start collecting and processing packets on network interface(s) */
int pksh_pkenable (int argc, char * argv [])
{
  char * progname = basename (argv [0]);
  char * sopts    = optlegitimate (lopts);

  /* Variables that are set according to the specified options */
  bool quiet      = false;

  int option;

  /* Local variables */
  char * name      = NULL;
  int as_parameter = 0;

  int snapshot     = DEFAULT_SNAPSHOT;
  int promiscuous  = 1;
  int timeout      = DEFAULT_TIMEOUT;
  int maxcount     = DEFAULT_MAXCOUNT;
  int hwsize       = DEFAULT_HW_SIZE;
  int ipsize       = DEFAULT_IP_SIZE;
  int hostsize     = DEFAULT_HOST_SIZE;

  char ebuf [PCAP_ERRBUF_SIZE] = { '\0' };
  char * ptrptr;

  int rc = 0;

  /* BPF filter and program */
  char * filter = NULL;
  struct bpf_program bpf_program;

  interface_t * interface = NULL;

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

	case OPT_SNAPSHOT:    snapshot = atoi (optarg); break;
	case OPT_PROMISCUOUS: promiscuous = 0;          break;
	case OPT_TIMEOUT:     timeout = atoi (optarg);  break;
	case OPT_MAXCOUNT:    maxcount = atoi (optarg); break;

	case 128: hwsize = atoi (optarg);   break;
	case 129: ipsize = atoi (optarg);   break;
	case 130: hostsize = atoi (optarg); break;
	}
    }

  /* Check if the user has specified one (or more) parameters */
  if (optind == argc)
    {
      /* None chosen via command line parameters, then find a suitable interface using pcap_lookupdev() */
      if (! (name = pcap_lookupdev (ebuf)))
	{
	  printf ("Unable to locate the default interface (%s).\n", ebuf);
	  if (getuid () && geteuid ())
	    {
	      printf ("Maybe you do not have permissions to look at packets on the network\n");
	      printf ("since opening a network interface in promiscuous mode is a privileged operation\n");
	    }
	  else
	    {
	      printf ("Please obtain the list of all suitable interfaces via the 'lsdev' command,\n");
	      printf ("then issue again this command passing the interface name as parameter\n");
	    }
	  return -1;
	}
      as_parameter = 0;
    }
  else
    {
      as_parameter = 1;

      /* More than one interface may be specified in a comma separated list */
      name = strtok_r (argv [optind ++], ",", & ptrptr);

      /* Build a filter from all remaining command line arguments */
      filter = argsjoin (argv + optind);
    }

  /* Start processing first interface */
  while (name)
    {
      /* Lookup for the given name in the table of enabled interfaces */
      interface = intfbyname (interfaces, name);
      if (! interface || interface -> status == INTERFACE_DOWN)
	{
	  /* never seen before or simply open before */
	  char value [12];

	  char ** cmdargv = NULL;

	  /* command name => argv [0] */
	  cmdargv = argsmore (cmdargv, "pkopen");

	  /* snapshot => -s snapshot */
	  if (snapshot != DEFAULT_SNAPSHOT)
	    {
	      cmdargv = argsmore (cmdargv, "-s");
	      sprintf (value, "%d", snapshot);
	      cmdargv = argsmore (cmdargv, value);
	    }

	  /* promiscuous => -p */
	  if (! promiscuous)
	    cmdargv = argsmore (cmdargv, "-p");

	  /* timeout => -t timeout */
	  if (timeout != DEFAULT_TIMEOUT)
	    {
	      cmdargv = argsmore (cmdargv, "-t");
	      sprintf (value, "%d", timeout);
	      cmdargv = argsmore (cmdargv, value);
	    }

	  if (hwsize != DEFAULT_HW_SIZE)
	    {
	      cmdargv = argsmore (cmdargv, "--hw");
	      sprintf (value, "%d", hwsize);
		cmdargv = argsmore (cmdargv, value);
	    }

	  if (ipsize != DEFAULT_IP_SIZE)
	    {
	      cmdargv = argsmore (cmdargv, "--ip");
	      sprintf (value, "%d", ipsize);
	      cmdargv = argsmore (cmdargv, value);
	    }

	  if (hostsize != DEFAULT_HOST_SIZE)
	    {
	      cmdargv = argsmore (cmdargv, "--ht");
	      sprintf (value, "%d", hostsize);
	      cmdargv = argsmore (cmdargv, value);
	    }

	  /* interface name */
	  cmdargv = argsmore (cmdargv, name);

	  /* Attempt to open the interface */
	  rc = pksh_pkopen (argslen (cmdargv), cmdargv);

	  argsclear (cmdargv);
	}
      else if (interface -> status == INTERFACE_ENABLED)
	{
	  /* Avoid to enable packet capturing several times for the same interface */
	  printf ("%s: packet capturing is already active for %s\n", argv [0], name);
	  rc = -1;
	}
      else
	rc = 0;     /* already open, avoid multiple open on the same network interface and silently continue */

      if (rc != -1)
	{
	  interface = intfbyname (interfaces, name);

	  /* Save the new filter expression */
	  if (filter)
	    {
	      if (interface -> filter)
		free (interface -> filter);
	      interface -> filter = strdup (filter);
	    }

	  if (interface -> filter)
	    {
	      /* Compile the optional 'filter' into a BPF program */
	      if (pcap_compile (interface -> pcap, & bpf_program, interface -> filter, 1, interface -> pcapnetmask) == -1)
		{
		  printf ("%s: cannot compile the filter [%s] (%s)\n", argv [0], interface -> filter, pcap_geterr (interface -> pcap));
		  free (interface -> filter);
		  interface -> filter = NULL;
		  rc = -1;
		}
	      else
		{
		  /* Apply the filter to the Packet Capture descriptor */
		  if (pcap_setfilter (interface -> pcap, & bpf_program) == -1)
		    {
		      printf ("%s: cannot set the filter [%s] (%s)\n", argv [0], interface -> filter, pcap_geterr (interface -> pcap));
		      free (interface -> filter);
		      interface -> filter = NULL;
		      rc = -1;
		    }
		}
	    }

	  if (rc != -1)
	    {
	      /* Set the max # of packets to capture */
	      if (maxcount)
		interface -> maxcount = maxcount;

	      /* Start a new thread to look at packets on this interface */
	      if (pthread_create (& interface -> tid, NULL, sniffer, interface))
		{
		  printf ("%s: cannot create a new thread for packet capturing from interface '%s'\n",
			  argv [0], interface -> name);
		  break;
		}

	      if (interface -> filter)
		printf ("started sniffer on interface '%s' with filter expression set to \"%s\" ...\n", name, interface -> filter);
	      else
		printf ("started sniffer on interface '%s' (no filter enabled)...\n", name);

	      /* Set the time the interface was enabled for sniffing */
	      gettimeofday (& interface -> started, NULL);

	      /* Change the status of the interface to ENABLED */
	      interface -> status = INTERFACE_ENABLED;

	      /* Update user prompt to include the active interface */
	      pksh_prompt (name);
	    }
	}

      /* Process next interface (if any) */
      name = as_parameter ? strtok_r (NULL, ",", & ptrptr) : NULL;
    }

  if (filter)
    free (filter);

  /* Bye bye! */
  return 0;
}
