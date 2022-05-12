/*
 * pksh - The Packet Shell
 *
 * R. Carbone (rocco@tecsiel.it)
 * 2008-2009, 2022
 *
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 */


/* System headers */
#include <stdlib.h>
#include <time.h>

/* Project header */
#include "pksh.h"

/* Identifiers */
#define NAME         "pkuptime"
#define BRIEF        "Tell how long the Packet Shell has been running"
#define SYNOPSIS     "pkutime [options]"
#define DESCRIPTION  "No description yet"

/* Public variable */
pksh_cmd_t cmd_uptime = { NAME, BRIEF, SYNOPSIS, DESCRIPTION, pksh_pkuptime };


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
  printf ("`%s' tells how long the program has been running and foreach enabled interface\n", progname);
  printf ("     for packets capturing it gives short info about about traffic seen on that interface\n");

  printf ("\n");
  printf ("Usage: %s [options]\n", progname);

  printf ("\n");
  printf ("Examples:\n");
  printf ("   %s                  # show how long the system has been up and info about all interfaces enabled to capture packets\n", progname);

  printf ("\n");
  printf ("Main options are:\n");
  printf ("   -h, --help                   only show this help message\n");
}


/* Tell how long the program has been running */
int pksh_pkuptime (int argc, char * argv [])
{
  char * progname = basename (argv [0]);
  char * sopts    = optlegitimate (lopts);

  /* Variables that are set according to the specified options */
  bool quiet      = false;

  int option;

  /* Local variables */
  time_t now = time (0);
  struct tm * tm = localtime (& now);
  interface_t ** intf;

  /* Lookup for the command in the static table of registered extensions */
  if (! cmd_by_name (progname))
    {
      printf ("%s: Command [%s] not found.\n", progname, progname);
      return -1;
    }

  /* Parse command line options to the application via standard system calls */
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

  /*
   * a simple banner, something like:
   * 7:07:18pm   up   0 days,  0:00:14,    1 interface
   */
  printf ("%2d:%02d:%02d%s   up %3d days, %2d:%02d:%02d,    %d interface%s\n",
	  tm -> tm_hour == 12 ? 12 : tm -> tm_hour % 12,
	  tm -> tm_min,
	  tm -> tm_sec,
	  tm -> tm_hour >= 13 ? "pm" : "am",
	  _days_ (now, pksh_run . boottime . tv_sec),
	  _hours_ (now, pksh_run . boottime . tv_sec),
	  _mins_ (now, pksh_run . boottime . tv_sec),
	  (int) (now - pksh_run . boottime . tv_sec) % 60,
	  intflen (interfaces), intflen (interfaces) > 1 ? "s" : "");

  /*
   * more information for each interface, something like
   * (eth0) -- tecsiel.it [159.69.218.55],   18 hosts,   183 Pkts / 14.5 Kb
   */
  intf = interfaces;
  while (intf && * intf)
    {
      host_t ** hosts = hostsall (* intf);
      int local = hostnolocal (hosts);
      int foreign = hostnoforeign (hosts);
      printf ("(%s) -- %s [%s],   %s Pkts / %s,   %d hosts [%d local   %d foreign]\n",
	      (* intf) -> name, (* intf) -> hostname, (* intf) -> ipaddr,
	      fmtpkts ((* intf) -> pkts_total), fmtbytes ((* intf) -> bytes_total),
	      local + foreign, local, foreign);
      intf ++;
      if (hosts)
	free (hosts);
    }

  /* Bye bye! */
  return 0;
}
