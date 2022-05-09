/*
 * pksh - The Packet Shell
 *
 * R. Carbone (rocco@tecsiel.it)
 * 2003, 2008-2009, 2022
 *
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Wrapper around original pksh_xxx() functions for use with tcsh
 */


/* Project header */
#include "pksh.h"


/* Identifiers */
#define NAME         "license"
#define BRIEF        "About the shell licence"
#define SYNOPSIS     "license [options]"
#define DESCRIPTION  "No description yet"

/* Public variable */
pksh_cmd_t cmd_license = { NAME, BRIEF, SYNOPSIS, DESCRIPTION, pksh_license };


/* GNU short options */
enum
{
  /* Startup */
  OPT_HELP  = 'h',
  OPT_QUIET = 'q'
};


/* GNU long options */
static struct option lopts [] =
{
  /* Startup */
  { "help",  no_argument, NULL, OPT_HELP  },
  { "quiet", no_argument, NULL, OPT_QUIET },

  { NULL,    0,           NULL, 0         }
};


/* Display the syntax */
static void usage (char * progname, struct option * options)
{
  /* longest option name */
  unsigned n = optmax (options);

  printf ("Startup:\n");
  usage_item (options, n, OPT_HELP,  "show this help message and exit");
  usage_item (options, n, OPT_QUIET, "run quietly");
}


/* The [license] command */
int pksh_license (int argc, char * argv [])
{
  char * progname = basename (argv [0]);
  char * sopts    = optlegitimate (lopts);

  /* Variables that are set according to the specified options */
  bool quiet      = false;

  int option;

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

  if (! quiet)
    {
      printf ("%s <%s>\n", PKSH_LICENSE, PKSH_LICENSE_URL);
      printf ("%s is distributed under the BSD License, meaning that you are free to redistribute, modify, or sell the software with almost no restrictions.\n", PKSH_PACKAGE);
      printf ("For the text of the license, see the license text at %s\n", PKSH_LICENSE_URL);
    }

  /* Bye bye! */
  return 0;
}
