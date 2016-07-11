/*
 * pkuptime.c - Tell how long the Packet Shell has been running
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
#include <time.h>

/* Private header file(s) */
#include "pksh.h"


/* How to use this command */
static void usage (char * cmd)
{
  printf ("`%s' tells how long the program has been running and foreach enabled interface\n", cmd);
  printf ("     for packets capturing it gives short info about about traffic seen on that interface\n");

  printf ("\n");
  printf ("Usage: %s [options]\n", cmd);

  printf ("\n");
  printf ("Examples:\n");
  printf ("   %s                  # show how long the system has been up and info about all interfaces enabled to capture packets\n", cmd);

  printf ("\n");
  printf ("Main options are:\n");
  printf ("   -h, --help                   only show this help message\n");
}


/* Tell how long the program has been running */
int pksh_pkuptime (int argc, char * argv [])
{
  /* GNU long options */
  static struct option const long_options [] =
    {
      { "help",        no_argument,       NULL, 'h' },

      { NULL,          0,                 NULL,  0 }
    };

  int option;

  /* Local variables */
  time_t now = time (0);
  struct tm * tm = localtime (& now);
  interface_t ** intf;

  /* Parse command line options to the application via standard system calls */
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

  /*
   * a simple banner, something like:
   * 7:07:18pm   up   0 days,  0:00:14,    1 interface
   */
  printf ("%2d:%02d:%02d%s   up %3d days, %2d:%02d:%02d,    %d interface%s\n",
	  tm -> tm_hour == 12 ? 12 : tm -> tm_hour % 12,
	  tm -> tm_min,
	  tm -> tm_sec,
	  tm -> tm_hour >= 13 ? "pm" : "am",
	  _days_ (now, boottime . tv_sec),
	  _hours_ (now, boottime . tv_sec),
	  _mins_ (now, boottime . tv_sec),
	  (int) (now - boottime . tv_sec) % 60,
	  intflen (interfaces), intflen (interfaces) > 1 ? "s" : "");

  /*
   * more information for each interface, something like
   * (eth0) -- svn.ntop.org [82.187.228.114],   18 hosts,   183 Pkts / 14.5 Kb
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

  return 0;
}
