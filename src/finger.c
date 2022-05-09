/*
 * pksh - The Packet Shell
 *
 * R. Carbone (rocco@tecsiel.it)
 * 2003, 2008-2009, 2022
 *
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 */


/* System headers */
#include <stdlib.h>

/* Project header */
#include "pksh.h"

/* Identifiers */
#define NAME         "pkfinger"
#define BRIEF        "Tell the hosts cache and display a lot of information for given hosts like the 'finger' command does for users"
#define SYNOPSIS     "pkfinger [options]"
#define DESCRIPTION  "No description yet"

/* Public variable */
pksh_cmd_t cmd_finger = { NAME, BRIEF, SYNOPSIS, DESCRIPTION, pksh_pkfinger };


/* GNU short options */
enum
{
  /* Startup */
  OPT_HELP      = 'h',
  OPT_QUIET     = 'q',

  OPT_INTERFACE = 'i'
};


/* GNU long options */
static struct option lopts [] =
{
  /* Startup */
  { "help",      no_argument,       NULL, OPT_HELP      },
  { "quiet",     no_argument,       NULL, OPT_QUIET     },

  { "interface", required_argument, NULL, OPT_INTERFACE },

  { NULL,        0,                 NULL, 0 }
};


/* Display the syntax */
static void usage (char * progname, struct option * options)
{
  printf ("`%s' tell and display the hosts cache on a given interface like the 'finger' command does for users\n", progname);

  printf ("\n");
  printf ("Usage: %s [options] [hostname [hostname] ...]\n", progname);

  printf ("\n");
  printf ("Examples:\n");
  printf ("   %s -i eth1 tecsiel.it       # display information on interface eth1 for host tecsiel.it\n", progname);

  printf ("\n");
  printf ("Main options are:\n");
  printf ("    -h, --help                         only show this help message\n");
  printf ("    -i, --interface                    specify network interface (e.g. eth0)\n");
}


/* Display detailed information for given hosts like the 'finger' command does for users */
int pksh_pkfinger (int argc, char * argv [])
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
	default: if (! quiet) printf ("Try '%s --help' for more information.\n", progname); return -1;

	  /* Startup */
	case OPT_HELP:  usage (progname, lopts); return 1;
	case OPT_QUIET: quiet = true;            break;

	case OPT_INTERFACE: name = optarg;       break;      /* network interface name */
	}
    }

  /* Check for mandatory arguments */
  if (argc == optind)
    {
      printf ("Missing host(s) (\"%s --help\" for help)\n", argv [0]);
      return -1;
    }

  /* Safe to play with the 'active' interface (if any) in case no specific one was chosen by the user */
  if (! name && ! (name = getintfname ()))
    {
      printf ("%s: no interface is currently enabled for packet sniffing\n", argv [0]);
      return -1;
    }

  /* Lookup for the given name in the table of enabled interfaces */
  if (! (interface = intfbyname (interfaces, name)))
    {
      printf ("%s: unknown interface %s\n", argv [0], name);
      return -1;
    }

  /* Avoid to print when no information are available */
  if (! (interface = intfbyname (interfaces, name)))
    {
      printf ("%s: unknown interface %s\n", argv [0], name);
      return -1;
    }

  /* Scan the hosts cache to display data according to user choices */
  while (optind < argc)
    {
      /* Get host information via its descriptor saved into the hash tables */
      host_t * host;

      if (! (host = hostbykey (interface, argv [optind])))
	{
	  printf ("%s: Unknown host\n", argv [optind ++]);
	  continue;
	}

      printf ("Everything you always wanted to know about host '%s':\n", argv [optind ++]);

      printf ("\n");

      printf ("Identity [%s]:\n", hostlocal (host) ? "Local" : "Remote");
      printf ("  ");
      unique_id_printf (host, NULL);
      if (! hostipless (host))
	printf (" ["),
	  printf ("%s", host -> ipaddr),
	  printf ("]");
      printf (" on %s ", name);

#if defined(FIXME)
      if (host -> fingerprint)
	printf ("running "),
	  os_fprintf (fd, host, NULL);
#endif /* FIXME */

      printf ("\n");

      /* Host Type */
      printf ("Host Type: ");

#if defined(FIXME)
      if (isServer (host))        printf ("Server ");
      if (isWorkstation (host))   printf ("Workstation ");
      if (isMasterBrowser (host)) printf ("Master Browser ");
      if (isPrinter (host))       printf ("Printer ");
      if (isBridgeHost (host))    printf ("Bridge ");
      if (isMultihomed (host))    printf ("Multihomed ");

      if (nameServerHost (host))  printf ("Name Server ");
      if (gatewayHost (host))     printf ("Gateway ");
      if (isSMTPhost (host))      printf ("SMTP Server ");
      if (isPOPhost (host))       printf ("POP Server ");
      if (isIMAPhost (host))      printf ("IMAP Server ");
      if (isDirectoryHost (host)) printf ("Directory Server");
      if (isFTPhost (host))       printf ("FTP Server ");
      if (isHTTPhost (host))      printf ("HTTP Server ");
      if (isWINShost (host))      printf ("WINS Server ");

      if (isDHCPClient (host))    printf ("BOOTP/DHCP Client ");
      if (isDHCPServer (host))    printf ("BOOTP/DHCP Server ");
#else
      printf ("currently unavailable");
#endif /* FIXME */

      printf ("\n");
      printf ("Timing:\n");
      printf ("  ");
      printf ("FirstSeen: "); firstseen_printf (host); printf ("\n");
      printf ("  ");
      printf ("LastSeen : "); lastseen_printf (host); printf ("\n");
      printf ("  ");
      printf ("Age      : "); age_uptime_printf (host); printf ("\n");
      printf ("  ");
      printf ("Idle     : "); idle_uptime_printf (host); printf ("\n");

      /* Network usage in terms of bytes */
      bytes_distribution (host);

      /* Network usage in terms of packets */
      packets_distribution (host);

      /* Network usage in terms of data-link and IP protocols */
      protocols_distribution (host);

      /* TCP Protocol distribution */
      tcp_protocols_distribution (host);

#if defined(FIXME)
      /* Traffic distribution by hour */
      bytes_all_by_hour (host);

      /* Contacted peers */
      contacted_peers (host);

      /* TCP/UDP ports usage */
      ports_usage (host);
#endif /* FIXME */
    }

  /* Bye bye! */
  return 0;
}
