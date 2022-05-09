/*
 * pksh - The Packet Shell
 *
 * R. Carbone (rocco@tecsiel.it)
 * 2003, 2008-2009, 2022
 *
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Display/Apply the BPF filter associated to network interface(s)
 */


/* System headers */
#include <stdlib.h>

/* Project header */
#include "pksh.h"

/* Identifiers */
#define NAME         "pkfilter"
#define BRIEF        "Display/Apply the BPF filter associated to network interface(s)"
#define SYNOPSIS     "pkfilter [options]"
#define DESCRIPTION  "No description yet"

/* Public variable */
pksh_cmd_t cmd_filter = { NAME, BRIEF, SYNOPSIS, DESCRIPTION, pksh_pkfilter };


/* GNU short options */
enum
{
  /* Startup */
  OPT_HELP        = 'h',
  OPT_QUIET       = 'q',

  OPT_INTERFACE   = 'i',
};


/* GNU long options */
static struct option lopts [] =
{
  /* Startup */
  { "help",          no_argument,       NULL, OPT_HELP        },
  { "quiet",         no_argument,       NULL, OPT_QUIET       },

  { "interface",     required_argument, NULL, OPT_INTERFACE   },

  { NULL,            0,                 NULL, 0               }
};


/* Display the syntax */
static void usage (char * progname, struct option * options)
{
  printf ("`%s' displays/applies a BPF filter associated to a network interface.\n", progname);
  printf ("Please refer to the Packet Capture Library for the syntax to use to set a BPF filter ('man pcap').\n");
  printf ("See also documentation of other networking applications if you are in trouble with\n");
  printf ("the meaning of filtering network traffic (e.g. tcpdump, ethereal, snort)\n");

  printf ("\n");
  printf ("Usage: %s [options] [-i interface] [ expression ]\n", progname);

  printf ("\n");
  printf ("Examples:\n");
  printf ("   %s                            # read and display the filter associated to the 'active' interface\n", progname);
  printf ("   %s -i eth1                    # read and display the filter associated to interface eth1\n", progname);
  printf ("   %s -i hme0 host tecsiel.it    # write the BPF filter for the interface hme0 to look at packets for host tecsiel.it\n", progname);

  printf ("\n");
  printf ("Main options are:\n");
  printf ("   -h, --help                          only show this help message\n");
  printf ("   -i, --interface                     specify the network interface (e.g. eth0)\n");
}


/* Get/Set the BPF filter associated to a network interface */
int pksh_pkfilter (int argc, char * argv [])
{
  char * progname = basename (argv [0]);
  char * sopts    = optlegitimate (lopts);

  /* Variables that are set according to the specified options */
  bool quiet      = false;

  int option;

  /* Local variables */
  char * name = NULL;

  /* BPF filter and program */
  char * filter;
  struct bpf_program bpf_program;

  interface_t * interface;

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

	case OPT_INTERFACE: name = optarg;  break;
	}
    }

  /* Check if the user has specified an interface on the command line otherwise use the 'active' interface (if any) */
  if (! name && ! (name = getintfname ()))
    {
      printf ("No interface is currently enabled for packet sniffing\n");
      return -1;
    }

  /* Lookup for the given name in the table of enabled interfaces */
  if (! (interface = intfbyname (interfaces, name)))
    {
      printf ("%s: unknown interface %s\n", argv [0], name);
      return -1;
    }

  /* Avoid to modify parameters for interfaces not yet enabled via Packet Capture Library */
  if (interface -> status != INTERFACE_ENABLED)
    {
      printf ("%s: interface %s has not yet enabled for packets capturing\n", argv [0], name);
      return -1;
    }

  /* Build a filter from all remaining command line arguments */
  if (optind < argc && (filter = argsjoin (argv + optind)))
    {
      /* Compile the optional 'filter' into a BPF program */
      if (pcap_compile (interface -> pcap, & bpf_program, filter, 1, interface -> pcapnetmask) == -1)
	{
	  printf ("%s: cannot compile the filter [%s] (%s)\n", argv [0], filter, pcap_geterr (interface -> pcap));
	  return -1;
	}

      /* And apply the filter to the pcap descriptor */
      if (pcap_setfilter (interface -> pcap, & bpf_program) == -1)
	{
	  printf ("%s: cannot set the filter [%s] (%s)\n", argv [0], filter, pcap_geterr (interface -> pcap));
	  return -1;
	}

      /* Save the new filter expression */
      if (filter)
	{
	  if (interface -> filter)
	    free (interface -> filter);
	  interface -> filter = strdup (filter);
	}
    }
  else
    {
      if (interface -> filter)
	printf ("filter expression on interface '%s' is currently set to: \"%s\"\n", name, interface -> filter);
      else
	printf ("no filter expression has been currently set on interface '%s'\n", name);
    }

  /* Bye bye! */
  return 0;
}
