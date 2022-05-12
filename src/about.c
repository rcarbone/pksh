/*
 * pksh - The Packet Shell
 *
 * R. Carbone (rocco@tecsiel.it)
 * 2008-2009, 2022
 *
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 */


/* System headers */
#include <sys/utsname.h>

/* Project header */
#include "pksh.h"

/* tcsh headers */
#include "config.h"
#include "patchlevel.h"


/* Identifiers */
#define NAME         "about"
#define BRIEF        "About the shell"
#define SYNOPSIS     "about [options]"
#define DESCRIPTION  "No description yet"

/* Public variable */
pksh_cmd_t cmd_about = { NAME, BRIEF, SYNOPSIS, DESCRIPTION, pksh_about };


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


/* The [about] command */
int pksh_about (int argc, char * argv [])
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
      struct utsname u;
      uname (& u);

      printf ("%s, ver. %s built for %s-%s on %s %s\n", PKSH_PACKAGE, PKSH_VERSION, u . sysname, u . machine, __DATE__, __TIME__);
      printf ("Copyright(c) 2022 %s\n", PKSH_AUTHOR);
      printf ("License: %s\n", PKSH_LICENSE_ID);
      printf ("\n");
      printf ("%s is provided AS IS and comes with ABSOLUTELY NO WARRANTY.\n", PKSH_PACKAGE);
      printf ("This is free software, and you are welcome to redistribute it under the terms of the license.\n");
      printf ("\n");
      printf ("Based on:\n");
      printf ("  tcsh v. %d.%d.%d - C shell with file name completion and command line editing - %s\n", REV, VERS, PATCHLEVEL, "Christos Zoulas <christos@NetBSD.org>");
      printf ("  %s  - Packet Capture library - %s\n", pcap_lib_version (), "The Tcpdump Group http://www.tcpdump.org");
    }

  /* Bye bye! */
  return 0;
}
