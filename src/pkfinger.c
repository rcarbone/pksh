/*
 * pkfinger.c - Tell the hosts cache and display a lot of information for
 *              given hosts like the 'finger' command does for users
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

/* Private header file(s) */
#include "pksh.h"


/* How to use this command */
static void usage (char * cmd)
{
  printf ("`%s' tell and display the hosts cache on a given interface\n", cmd);

  printf ("\n");
  printf ("Usage: %s [options] [hostname [hostname] ...]\n", cmd);

  printf ("\n");
  printf ("Examples:\n");
  printf ("   %s -i eth1 svn.ntop.org     # display information on interface eth1 for host svn.ntop.org\n", cmd);

  printf ("\n");
  printf ("Main options are:\n");
  printf ("    -h, --help                         only show this help message\n");
  printf ("    -i, --interface                    specify network interface (e.g. eth0)\n");
}


/* It queries the hosts cache and displays information
 * for given hosts like the 'finger' command does for users
 */
int pksh_pkfinger (int argc, char * argv [])
{
  /* GNU long options */
  static struct option const long_options [] =
    {
      /* G e n e r a l  o p t i o n s  (P O S I X) */

      { "help",      no_argument,       NULL, 'h' },
      { "interface", required_argument, NULL, 'i' },

      { NULL,        0,                 NULL, 0 }
    };

  int option;

  /* Local variables */
  char * name = NULL;
  interface_t * interface;

  /* Parse command line options */
#define OPTSTRING "hi:"

  optind = 0;
  optarg = NULL;
  while ((option = getopt_long (argc, argv, OPTSTRING, long_options, NULL)) != -1)
    {
      switch (option)
	{
	default:  usage (argv [0]); return -1;

	case 'h': usage (argv [0]); return 0;

	case 'i': name = optarg; break;
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

  return 0;
}
