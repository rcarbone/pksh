/*
 * pkfilter.c - Display/Apply the BPF filter associated to network interface(s)
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

/* Private header file(s)*/
#include "pksh.h"


/* How to use this command */
static void usage (char * cmd)
{
  printf ("`%s' displays/applies a BPF filter associated to a network interface.\n", cmd);
  printf ("Please refer to the Packet Capture Library for the syntax to use to set a BPF filter ('man pcap').\n");
  printf ("See also documentation of other networking applications if you are in trouble with\n");
  printf ("the meaning of filtering network traffic (e.g. ntop, tcpdump, ethereal, snort)\n");

  printf ("\n");
  printf ("Usage: %s [options] [-i interface] [ expression ]\n", cmd);

  printf ("\n");
  printf ("Examples:\n");
  printf ("   %s                            # read and display the filter associated to the 'active' interface\n", cmd);
  printf ("   %s -i eth1                    # read and display the filter associated to interface eth1\n", cmd);
  printf ("   %s -i hme0 host svn.ntop.org  # write the BPF filter for the interface hme0 to look at packets for host svn.ntop.org\n", cmd);

  printf ("\n");
  printf ("Main options are:\n");
  printf ("   -h, --help                          only show this help message\n");
  printf ("   -i, --interface                     specify the network interface (e.g. eth0)\n");
}


/* Get/Set the BPF filter associated to a network interface */
int pksh_pkfilter (int argc, char * argv [])
{
  /* GNU long options */
  static struct option const long_options [] =
    {
      { "help",        no_argument,       NULL, 'h' },
      { "interface",   required_argument, NULL, 'i' },

      { NULL,          0,                 NULL,  0 }
    };

  int option;

  /* Local variables */
  char * name = NULL;

  /* BPF filter and program */
  char * filter;
  struct bpf_program bpf_program;

  interface_t * interface;

  /* Parse command line options */
#define OPTSTRING "hi:"

  optind = 0;
  optarg = NULL;
  while ((option = getopt_long (argc, argv, OPTSTRING, long_options, NULL)) != -1)
    {
      switch (option)
	{
	default:  usage (argv [0]); return -1;

	case 'h': usage (argv [0]); return 0;

	case 'i': name = optarg;  break;
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

  return 0;
}
