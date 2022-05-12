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
#define NAME         "pkswap"
#define BRIEF        "Manage the stack of last referenced network interfaces"
#define SYNOPSIS     "pkswap [options]"
#define DESCRIPTION  "No description yet"

/* Public variable */
pksh_cmd_t cmd_swap = { NAME, BRIEF, SYNOPSIS, DESCRIPTION, pksh_pkswap };

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
  printf ("`%s' prints current network interface information in a format readable for humans\n",
	  progname);

  printf ("\n");
  printf ("Usage: %s [options] [interface]\n", progname);

  printf ("\n");
  printf ("Examples:\n");
  printf ("   %s                     # leave the active interface and restore latest referenced (if any)\n", progname);
  printf ("   %s eth1                # leave the active interface and restore interface eth1\n", progname);

  printf ("\n");
  printf ("Main options are:\n");
  printf ("   -h, --help                   only show this help message\n");
}


/* Swap between last referenced network interfaces (when possible) */
int pksh_pkswap (int argc, char * argv [])
{
  char * progname = basename (argv [0]);
  char * sopts    = optlegitimate (lopts);

  /* Variables that are set according to the specified options */
  bool quiet      = false;

  int option;

  /* Local variables */
  char * name = NULL;
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

  /* Check if the user has specified an interface on the command line
   * otherwise use the latest referenced one (if any) */
  if (optind < argc)
    name = argv [optind ++];
  else
    {
      if (! (interface = lastestintf ()))
	{
	  printf ("%s: no more interface\n", argv [0]);
	  return -1;
	}
      name = interface -> name;
    }

  /* Lookup for the given name in the table of enabled interfaces */
  if (! (interface = intfbyname (interfaces, name)))
    {
      printf ("%s: unknown interface %s\n", argv [0], name);
      return -1;
    }

  /* No action in the event the chosen interface matches the active */
  if (interface == activeintf ())
    return -1;

  /* Swap now */
  setactiveintf (interface);

  /* Update user prompt to include the active interface */
  pksh_prompt (name);

  /* Bye bye! */
  return 0;
}
