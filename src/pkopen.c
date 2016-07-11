/*
 * pkopen.c - Open network interface(s) to look at packets on the network
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
 *
 */


/* Operating System header file(s) */
#include <stdlib.h>
#include <unistd.h>

/* Private header file(s) */
#include "pksh.h"


/* How to use this command */
static void usage (char * cmd)
{
  printf ("`%s' attempts to open one (or more) network interface(s) to look at packets on the network.\n", cmd);
  printf ("More than one interface may be specified in a comma separated list.\n");
  printf ("On Linux systems an argument of 'any' can be used to capture packets from all available interfaces.\n");
  printf ("Please refer to the pcap (Packet Capture) library for more info about filter expressions ('man pcap').\n");
  printf ("See also documentation of other networking applications if you are in trouble with\n");
  printf ("the meaning of filtering network traffic (e.g. ntop, tcpdump, ethereal, snort)\n");

  printf ("\n");
  printf ("Usage: %s [options] [interface[,interface] [ expression ]]\n", cmd);

  printf ("\n");
  printf ("Examples:\n");
  printf ("   %s                         # find the first available interface and open it\n", cmd);
  printf ("   %s eth1                    # open interface eth1\n", cmd);
  printf ("   %s eth2,eth0,eth1          # open interfaces eth2, eth0 and eth1 in this order. Latest is the 'active' interface\n", cmd);
  printf ("   %s hme0 host svn.ntop.org  # open interface hme0 to look at packets only for host svn.ntop.org\n", cmd);

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
  /* GNU long options */
  static struct option const long_options [] =
    {
      { "help",           no_argument,       NULL, 'h' },
      { "snapshot",       required_argument, NULL, 's' },
      { "promiscuous",    no_argument,       NULL, 'p' },
      { "timeout",        required_argument, NULL, 't' },

      { "hardware-size",  required_argument, NULL,  128 },
      { "ip-size" ,       required_argument, NULL,  129 },
      { "hostname-size",  required_argument, NULL,  130 },

      { "hw",             required_argument, NULL,  128 },
      { "ip",             required_argument, NULL,  129 },
      { "ht",             required_argument, NULL,  130 },

      { NULL,             0,                 NULL,  0 }
    };

  int option;

  /* Local variables */
  int rc = 0;
  char * name = NULL;
  int as_parameter = 0;

  int snapshot = DEFAULT_SNAPSHOT;
  int promiscuous = 1;
  int timeout = DEFAULT_TIMEOUT;
  int hwsize = DEFAULT_HW_SIZE;
  int ipsize = DEFAULT_IP_SIZE;
  int hostsize = DEFAULT_HOST_SIZE;

  char ebuf [PCAP_ERRBUF_SIZE] = { '\0' };
  char * ptrptr;

  /* pcap descriptor */
  pcap_t * pcap = NULL;
  interface_t * interface;

  /* BPF filter */
  char * filter = NULL;

  /* Parse command line options */
#define OPTSTRING "hs:pt:"

  optind = 0;
  optarg = NULL;
  while ((option = getopt_long (argc, argv, OPTSTRING, long_options, NULL)) != -1)
    {
      switch (option)
	{
	default:  usage (argv [0]); return -1;

	case 'h': usage (argv [0]); return 0;

	case 's': snapshot = atoi (optarg); break;
	case 'p': promiscuous = 0;          break;
	case 't': timeout = atoi (optarg);  break;

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
		  pkshprompt (name);
		}
	    }
	}

      /* Process next interface (if any) */
      name = as_parameter ? strtok_r (NULL, ",", & ptrptr) : NULL;
    }

  if (filter)
    free (filter);

  return rc;
}
