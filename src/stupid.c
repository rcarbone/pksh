/*
 * stupid.c - The simplest 'pksh' built-in extension
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
#include <stdio.h>

/* Private header file(s) */
#include "pksh.h"


/* How to use this command */
static void usage (char * cmd)
{
  printf ("`%s' the simplest extension\n", cmd);

  printf ("\n");
  printf ("Usage: %s [options]\n", cmd);

  printf ("\n");
  printf ("Main options are:\n");
  printf ("    -h, --help       only show this help message\n");
}


/* A dummy and stupid extesion to the pksh.  It does nothing */
int stupid (int argc, char * argv [])
{
  /* GNU long options */
  static struct option const long_options [] =
    {
      /* G e n e r a l  o p t i o n s  (P O S I X) */

      { "help",                               no_argument,       NULL, 'h' },

      { NULL,                                 0,                 NULL, 0 }
    };

  /* Local variables */

  int option;

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

  return 0;
}
