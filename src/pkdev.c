/*
 * pkdev.c - List all network interfaces suitable for being used with the Packet Shell
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
#include <errno.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#if defined(sun)
# include <sys/sockio.h>
#endif

/* Private header file(s) */
#include "pksh.h"


/* How to use this command */
static void usage (char * command)
{
  printf ("`%s' displays the list of network interface(s) that can be used to look at packets on the network\n", command);

  printf ("\n");
  printf ("Usage: %s [options]\n", command);

  printf ("\n");
  printf ("Examples:\n");
  printf ("   %s                     # show all the avaialable interface(s) for packet capturing\n", command);

  printf ("\n");
  printf ("Main options are:\n");
  printf ("   -h, --help                   only show this help message\n");
}


/*
 * Show the list of available network interfaces attached to the system.
 * To be included in the list the interface must be configured up
 * and it should be accessible via the pcap library
 */
int pksh_pkdev (int argc, char * argv [])
{
  /* GNU long options */
  static struct option const long_options [] =
    {
      { "help",        no_argument,       NULL, 'h' },

      { NULL,          0,                 NULL,  0 }
    };

  int option;

  /* Local variables */
  int fd;
  int found = 0;      /* # of configured interfaces */
  int avail = 0;      /* # of available interfaces */
  int i;
  int once = 0;

  /* Array of structures (memory buffer for SIOCGIFCONF) */
  struct ifreq room [MAX_NUM_DEVICES] ;
  struct ifconf ifc;
  struct ifreq * first;
  struct ifreq * last;
  struct ifreq * current;
  struct ifreq flags;                             /* flags for the interface */

  /* pcap variables */
  char ebuf [PCAP_ERRBUF_SIZE] = {0};
  pcap_t * pcap;

  memset (& room, 0, sizeof (room));

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

  if (optind < argc)
    {
      printf ("\nWrong option(s): \" ");
      while (optind < argc)
	printf ("%s ", argv [optind ++]);
      printf ("\"\n");
      usage (argv [0]);
      printf ("\n");
      return -1;
    }

  /* Open a socket to query for network configuration parameters */
  fd = socket (AF_INET, SOCK_DGRAM, 0);
  if (fd == -1)
    {
      printf ("%s: cannot open socket: errno = %d\n", argv [0], errno);
      return -1;
    }

  /* Set output memory variables */
  ifc . ifc_len = sizeof (room);
  ifc . ifc_buf = (caddr_t) room;

  /* Retrieve interface list for this system */
  if (ioctl (fd, SIOCGIFCONF, & ifc) == -1 || ifc . ifc_len < sizeof (struct ifreq))
    {
      printf ("%s: cannot retrieve network interface list: errno = %d\n", argv [0], errno);
      close (fd);
      return -1;
    }

  /* Set pointers to the returned buffer */
  current = first = (struct ifreq *) ifc . ifc_req;
  last = (struct ifreq *) (first + ifc . ifc_len);

  /* This is the # of configured interfaces at this time on this system */
  found = (last - first) / sizeof (struct ifreq);

  if (found)
    printf ("%d interface(s) were found on this system\n", found);

  for (i = 0; i < found; i ++, current ++)
    {
      /* Skip dummy and virtual interfaces */
      if (! strncmp (current -> ifr_name, "dummy", 5) || strchr (current -> ifr_name, ':'))
	continue;

      /* Some systems return multiple entries if the interface has multi addresses */
      memset (& flags, 0, sizeof (flags));
      strncpy (flags . ifr_name, current -> ifr_name, sizeof (flags . ifr_name));

      /* Get the interface flags */
      if (ioctl (fd, SIOCGIFFLAGS, & flags) == -1)
	{
	  if (errno == ENXIO)
	    continue;

	  printf ("cannot get flags for interface %.*s: errno = %d\n", (int) sizeof (flags . ifr_name), flags . ifr_name, errno);
	  continue;
	}

      /* Show, and count, only the enabled interfaces */
      if (! (flags . ifr_flags & IFF_UP))
	continue;

      /* Be sure the pcap library can access it */
      if (! (pcap = pcap_open_live (flags . ifr_name, 68, 1, 100, ebuf)))
	continue;
      pcap_close (pcap);

      avail ++;
      if (! once)
	printf ("The list of those suitable for being used with %s is:\n", argv [0]);
      once = 1;
      printf ("%d. %.*s\n", avail, (int) sizeof (flags . ifr_name), flags . ifr_name);
    }

  close (fd);

  if (! avail)
    {
      printf ("No interface suitable for packet capture was found.\n");
      if (getuid () && geteuid ())
	printf ("Check if you have permissions to look at packets on the network\n"),
	  printf ("since opening a network interface in promiscuous mode is a privileged operation\n");
      return -1;
    }

  return 0;
}
