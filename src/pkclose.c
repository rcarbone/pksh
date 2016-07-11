/*
 * pkclose.c - Close network interface(s)
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
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= *
 */


/* Private header file(s) */
#include "pksh.h"


/* How to use this command */
static void usage (char * cmd)
{
  printf ("`%s' attempts to close one (or more) network interface(s).\n", cmd);
  printf ("More than one interface may be specified in a comma separated list\n");

  printf ("\n");
  printf ("Usage: %s [options] [interface[,interface]\n", cmd);

  printf ("\n");
  printf ("Examples:\n");
  printf ("   %s                 # close the active interface\n", cmd);
  printf ("   %s eth1            # close interface eth1\n", cmd);
  printf ("   %s eth2,eth0,eth1  # close interfaces eth2, eth0 and eth1 in this order\n", cmd);

  printf ("\n");
  printf ("Main options are:\n");
  printf ("   -h, --help                only show this help message\n");
}


/* Deallocate a pcap descriptor and close the network resources */
int pksh_pkclose (int argc, char * argv [])
{
  /* GNU long options */
  static struct option const long_options [] =
    {
      { "help", no_argument, NULL, 'h' },

      { NULL,   0,           NULL,  0 }
    };

  int option;

  /* Local variables */
  char * name = NULL;
  int as_parameter = 0;
  char * ptrptr;

  interface_t * interface;

  /* Parse command line options */
#define OPTSTRING "h"

  optind = 0;
  optarg = NULL;
  while ((option = getopt_long (argc, argv, OPTSTRING, long_options, NULL)) != -1)
    {
      switch (option)
	{
	default:  usage (argv [0]); return -1;

	case 'h': usage (argv [0]); return 0;
	}
    }

  if (optind >= argc)
    {
      /* Safe to play with the 'active' interface (if any) in case no specific one was chosen by the user */
      /* Lookup for the name of the active interface in the table of the enabled interfaces */
      if (! name && ! (name = getintfname ()))
	{
	  printf ("%s: no interface is currently enabled for packet sniffing\n", argv [0]);
	  return -1;
	}
      as_parameter = 0;
    }
  else
    {
      as_parameter = 1;

      /* More than one interface may be specified in a comma separated list */
      name = strtok_r (argv [optind ++], ",", & ptrptr);
    }

  /* Start processing first interface */
  while (name)
    {
      /* Lookup for the given name in the table of enabled interfaces */
      if (! (interface = intfbyname (interfaces, name)))
	printf ("%s: unknown interface %s\n", argv [0], name);
      else
	{
	  /* This should allow the sniffer thread to terminate as soon as possible */
	  interface -> status = INTERFACE_READY;

	  /* Free the descriptor from the table of network interfaces */
	  interfaces = intfsub (interfaces, name);

	  /* Keep track of the last active interface */
	  resetactiveintf (interface);

	  /* Update user prompt to include the previous interface (if any) */
	  pkshprompt (getintfname ());
	}

      /* Process next interface (if any) */
      name = as_parameter ? strtok_r (NULL, ",", & ptrptr) : NULL;
    }

  return 0;
}
