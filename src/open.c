/*
 * pksh - The Packet Shell
 *
 * R. Carbone (rocco@tecsiel.it)
 * 2003, 2008-2009, 2022
 *
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Open network interface(s) to look at packets on the network
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
#define NAME         "pkopen"
#define BRIEF        "Enable packets capture on network interface(s)"
#define SYNOPSIS     "pkopen [options]"
#define DESCRIPTION  "No description yet"

/* Public variable */
pksh_cmd_t cmd_open = { NAME, BRIEF, SYNOPSIS, DESCRIPTION, pksh_pkopen };


/* GNU short options */
enum
{
  /* Startup */
  OPT_HELP        = 'h',
  OPT_QUIET       = 'q',

  OPT_SNAPSHOT    = 's',
  OPT_PROMISCUOUS = 'p',
  OPT_TIMEOUT     = 't'
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

  { "hardware-size", required_argument, NULL, 128             },
  { "ip-size",       required_argument, NULL, 129             },
  { "hostname-size", required_argument, NULL, 130             },

  { "hw",            required_argument, NULL, 128             },
  { "ip",            required_argument, NULL, 129             },
  { "ht",            required_argument, NULL, 130             },

  { NULL,            0,                 NULL, 0               }
};


/* Display the syntax */
static void usage (char * progname, struct option * options)
{
  printf ("`%s' attempts to open one (or more) network interface(s) to look at packets on the network.\n", progname);
  printf ("More than one interface may be specified in a comma separated list.\n");
  printf ("On Linux systems an argument of 'any' can be used to capture packets from all available interfaces.\n");
  printf ("Please refer to the pcap (Packet Capture) library for more info about filter expressions ('man pcap').\n");
  printf ("See also documentation of other networking applications if you are in trouble with\n");
  printf ("the meaning of filtering network traffic (e.g. tcpdump, ethereal, snort)\n");

  printf ("\n");
  printf ("Usage: %s [options] [interface[,interface] [ expression ]]\n", progname);

  printf ("\n");
  printf ("Examples:\n");
  printf ("   %s                         # find the first available interface and open it\n", progname);
  printf ("   %s eth1                    # open interface eth1\n", progname);
  printf ("   %s eth2,eth0,eth1          # open interfaces eth2, eth0 and eth1 in this order. Latest is the 'active' interface\n", progname);
  printf ("   %s hme0 host tecsiel.it    # open interface hme0 to look at packets only for host tecsiel.it\n", progname);

  printf ("\n");
  printf ("Main options are:\n");
  printf ("   -h, --help                       only show this help message\n");
  printf ("   -s, --snapshot                   specify the maximum number of bytes to capture (default %d)\n", DEFAULT_SNAPSHOT);
  printf ("   -p, --promiscuous                disable promiscuous mode of operation\n");
  printf ("   -t, --timeout                    specify the read timeout in ms (default %d)\n", DEFAULT_TIMEOUT);

  printf ("  --hw, --hardware-size             specify hash table size for hardware identifiers (default %d)\n", DEFAULT_HW_SIZE);
  printf ("  --ip, --ip-size                   specify hash table size for IP address (default %d)\n", DEFAULT_IP_SIZE);
  printf ("  --ht, --hostname-size             specify hash table size for hostnames (default %d)\n", DEFAULT_HOST_SIZE);
}


/* Open a network interface to look at packets on the network */
int pksh_pkopen (int argc, char * argv [])
{
  char * progname = basename (argv [0]);
  char * sopts    = optlegitimate (lopts);

  /* Variables that are set according to the specified options */
  bool quiet      = false;

  int option;

  /* Local variables */
  int rc = 0;
  char * name = NULL;
  int as_parameter = 0;

  int snapshot    = DEFAULT_SNAPSHOT;
  int promiscuous = 1;
  int timeout     = DEFAULT_TIMEOUT;
  int hwsize      = DEFAULT_HW_SIZE;
  int ipsize      = DEFAULT_IP_SIZE;
  int hostsize    = DEFAULT_HOST_SIZE;

  char ebuf [PCAP_ERRBUF_SIZE] = { '\0' };
  char * ptrptr;

  /* pcap descriptor */
  pcap_t * pcap = NULL;
  interface_t * interface;

  /* BPF filter */
  char * filter = NULL;

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

	case 128: hwsize = atoi (optarg);   break;
	case 129: ipsize = atoi (optarg);   break;
	case 130: hostsize = atoi (optarg); break;
	}
    }

  /* Check if the user has specified one (or more) parameters */
  if (optind >= argc)
    {
      /* None chosen via command line parameters, then find a suitable interface using pcap_lookupdev() */
      if (! (name = pcap_lookupdev (ebuf)))
	{
	  printf ("Unable to locate the default interface (%s).\n", ebuf);
	  if (getuid () && geteuid ())
	    printf ("Maybe you do not have permissions to look at packets on the network\n"),
	      printf ("since opening a network interface in promiscuous mode is a privileged operation\n");
	  else
	    printf ("Please obtain the list of all suitable interfaces via the 'lsdev' command,\n"),
	      printf ("then issue again this command passing the interface name as parameter\n");
	  return -1;
	}
      printf ("interface %s has been chosen by default for packet sniffing\n", name);
      as_parameter = 0;
    }
  else
    {
      int roomsize = 0;

      as_parameter = 1;

      /* More than one interface may be specified in a comma separated list */
      name = strtok_r (argv [optind ++], ",", & ptrptr);

      /* Build a filter from all remaining command line arguments */
      roomsize = 0;
      filter = NULL;
      while (optind < argc)
	{
	  roomsize += (strlen (argv [optind]) + 1 + 1);
	  filter = realloc (filter, roomsize);
	  strcat (filter, argv [optind ++]);
	  if (optind != argc - 1)
	    strcat (filter, " ");
	}
    }

  /* Start processing first interface */
  while (name)
    {
      /*
       * Lookup for the given name in the table of enabled interfaces
       * (to avoid multiple open on the same network interface)
       */
      if ((interface = intfbyname (interfaces, name)))
	printf ("%s: interface %s already enabled for packet capturing. Skipping it!\n", argv [0], name);
      else
	{
	  /* Time to initialize pcap library for the specified interface */
	  if (! (pcap = pcap_open_live (name, snapshot, promiscuous, timeout, ebuf)))
	    {
	      rc = -1;
	      printf ("%s: cannot open interface %s (%s)\n", argv [0], name, ebuf);
	    }
	  else
	    {
	      /* Get a new descriptor and save current parameters to the table of interfaces managed by this program */
	      if (! (interfaces = intfadd (interfaces, name, snapshot, promiscuous, timeout, filter, pcap, & interface)))
		{
		  rc = -1;
		  printf ("Sorry! There is no space left. Too many open network interfaces\n");

		  /* Release the pcap descriptor */
		  pcap_close (pcap);
		}
	      else
		{
		  /* Initialize the hash tables for host management */
		  interface -> hwnames . size = hwsize;
		  hash_table_init (& interface -> hwnames);

		  interface -> ipnames . size = ipsize;
		  hash_table_init (& interface -> ipnames);

		  interface -> hostnames . size = hostsize;
		  hash_table_init (& interface -> hostnames);

		  /* Keep track of the last active interface */
		  setactiveintf (interface);

		  /* Update user prompt to include the active interface */
		  pksh_prompt (name);
		}
	    }
	}

      /* Process next interface (if any) */
      name = as_parameter ? strtok_r (NULL, ",", & ptrptr) : NULL;
    }

  if (filter)
    free (filter);

  /* Bye bye! */
  return rc;
}
