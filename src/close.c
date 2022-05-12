/*
 * pksh - The Packet Shell
 *
 * R. Carbone (rocco@tecsiel.it)
 * 2008-2009, 2022
 *
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 */


/* Project header */
#include "pksh.h"


/* Identifiers */
#define NAME         "pkclose"
#define BRIEF        "Close network interface(s)"
#define SYNOPSIS     "pkclose [options]"
#define DESCRIPTION  "No description yet"

/* Public variable */
pksh_cmd_t cmd_close = { NAME, BRIEF, SYNOPSIS, DESCRIPTION, pksh_pkclose };


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
  printf ("`%s' attempts to close one (or more) network interface(s).\n", progname);
  printf ("More than one interface may be specified in a comma separated list\n");

  printf ("\n");
  printf ("Usage: %s [options] [interface[,interface]\n", progname);

  printf ("\n");
  printf ("Examples:\n");
  printf ("   %s                 # close the active interface\n", progname);
  printf ("   %s eth1            # close interface eth1\n", progname);
  printf ("   %s eth2,eth0,eth1  # close interfaces eth2, eth0 and eth1 in this order\n", progname);

  printf ("\n");
  printf ("Main options are:\n");
  printf ("   -h, --help                only show this help message\n");
}


/* Deallocate a pcap descriptor and close the network resources */
int pksh_pkclose (int argc, char * argv [])
{
  char * progname = basename (argv [0]);
  char * sopts    = optlegitimate (lopts);

  /* Variables that are set according to the specified options */
  bool quiet      = false;

  int option;

  /* Local variables */
  char * name = NULL;
  int as_parameter = 0;
  char * ptrptr;

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
	  pksh_prompt (getintfname ());
	}

      /* Process next interface (if any) */
      name = as_parameter ? strtok_r (NULL, ",", & ptrptr) : NULL;
    }

  /* Bye bye! */
  return 0;
}
