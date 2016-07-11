/*
 * pkswap.c - Manage the stack of last referenced network interfaces
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


/* Private header file(s) */
#include "pksh.h"


/* How to use this command */
static void usage (char * cmd)
{
  printf ("`%s' prints current network interface information in a format readable for humans\n",
	  cmd);

  printf ("\n");
  printf ("Usage: %s [options] [interface]\n", cmd);

  printf ("\n");
  printf ("Examples:\n");
  printf ("   %s                     # leave the active interface and restore latest referenced (if any)\n", cmd);
  printf ("   %s eth1                # leave the active interface and restore interface eth1\n", cmd);

  printf ("\n");
  printf ("Main options are:\n");
  printf ("   -h, --help                   only show this help message\n");
}


/* Swap between last referenced network interfaces (when possible) */
int pksh_pkswap (int argc, char * argv [])
{
  /* GNU long options */
  static struct option const long_options [] =
    {
      { "help",        no_argument,       NULL, 'h' },

      { NULL,          0,                 NULL,  0 }
    };

  int option;

  /* Local variables */
  char * name = NULL;
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
  pkshprompt (name);

  return 0;
}
