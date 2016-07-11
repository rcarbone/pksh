/*
 * packets.c - Display detailed information about packets viewed on network interface(s)
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
  printf ("`%s' provides a dynamic real-time view of the amount of packets in and out on a given interface\n", cmd);

  printf ("\n");
  printf ("Usage: %s [options] [hostname [hostname] ...]\n", cmd);

  printf ("\n");
  printf ("Examples:\n");
  printf ("   %s -i eth1                      # display the amount of packets viewed on interface eth1 using default sorting\n", cmd);
  printf ("   %s --sort-by-mac-address -r     # display a reverse sorted table according to the MAC addresses\n", cmd);

  printf ("\n");
  printf ("Main options are:\n");
  printf ("    -h, --help                            only show this help message\n");
  printf ("    -i, --interface                       specify network interface (e.g. eth0)\n");
  printf ("    -n, --numeric                         do not resolve names\n");
  printf ("    -l, --local                           include only local hosts\n");
  printf ("    -f, --foreign                         include only remote hosts\n");
  printf ("    -p, --no-ipless                       exclude hosts that do not have an IP address\n");
  printf ("    -P, --ipless-only                     include only hosts that do not have an IP address\n");
  printf ("    -d, --exclude-unresolved              exclude hosts that do not have a symbolic address\n");
  printf ("    -D, --unresolved-only                 include only hosts that do not have a symbolic address\n");

  printf ("\n");
  printf ("Display options are:\n");
  printf ("    -x, --exclude-defaults                exclude default formatting columns\n");
  printf ("  --i0, --include-total-all               include column with # of total packets (all protocols)\n");
  printf ("  --i1, --include-total-sent              include column with # of total packets sent\n");
  printf ("  --i2, --include-total-recv              include column with # of total packets received\n");
  printf ("  --i3, --include-broadcast-sent          include column with # of data-link broadcast packets sent\n");
  printf ("  --i4, --include-multicast-sent          include column with # of data-link multicast packets sent\n");
  printf ("  --i5, --include-ip-broadcast-sent       include column with # of IP broadcast packets sent\n");
  printf ("  --i6, --include-ip-multicast-sent       include column with # of IP multicast packets sent\n");

  printf ("\n");
  printf ("Sorting options are:\n");
  printf ("    -u, --unsort                          do not sort (default sort by tot # of packets sent/recv)\n");
  printf ("    -r, --reverse                         reverse the result of sorting\n");
  printf ("  --s0, --sort-by-mac-address             sort the hosts cache by MAC addresses\n");
  printf ("  --s1, --sort-by-ip-address              sort the hosts cache by IP addresses\n");
  printf ("  --s2, --sort-by-hostname                sort the hosts cache by hostnames\n");

  printf ("  --s3, --sort-by-pkts-all                sort the hosts cache by total # of packets sent and received\n");
  printf ("  --s4, --sort-by-pkts-sent               sort the hosts cache by total # of packets sent\n");
  printf ("  --s5, --sort-by-pkts-recv               sort the hosts cache by total # of packets received\n");
  printf ("  --s6, --sort-by-broadcast-pkts-sent     sort the hosts cache by total # of data-link broadcast packets sent\n");
  printf ("  --s7, --sort-by-multicast-pkts-sent     sort the hosts cache by total # of data-link multicast packets sent\n");
  printf ("  --s8, --sort-by-ip-broadcast-pkts-sent  sort the hosts cache by total # of IP broadcast packets sent\n");
  printf ("  --s9, --sort-by-ip-multicast-pkts-sent  sort the hosts cache by total # of IP multicast packets sent\n");
}


/* Show detailed information about the current traffic (in terms of packets) on a given interface */
int pksh_packets (int argc, char * argv [])
{
  /* GNU long options */
  static struct option const long_options [] =
    {
      /* G e n e r a l  o p t i o n s  (P O S I X) */

      { "help",                           no_argument,       NULL, 'h' },
      { "interface",                      required_argument, NULL, 'i' },
      { "numeric",                        no_argument,       NULL, 'n' },
      { "unsort",                         no_argument,       NULL, 'u' },
      { "reverse",                        no_argument,       NULL, 'r' },
      { "local",                          no_argument,       NULL, 'l' },
      { "foreign",                        no_argument,       NULL, 'f' },
      { "exclude-ipless",                 no_argument,       NULL, 'p' },
      { "ipless-only",                    no_argument,       NULL, 'P' },
      { "exclude-unresolved",             no_argument,       NULL, 'd' },
      { "unresolved-only",                no_argument,       NULL, 'D' },
      { "exclude-defaults",               no_argument,       NULL, 'x' },

      /* C o l u m n  o p t i o n s  (G N U) */

      { "include-total-all",              no_argument,       NULL, 128 },
      { "include-total-sent",             no_argument,       NULL, 129 },
      { "include-total-recv",             no_argument,       NULL, 130 },
      { "include-broadcast-sent",         no_argument,       NULL, 131 },
      { "include-multicast-sent",         no_argument,       NULL, 132 },
      { "include-ip-broadcast-sent",      no_argument,       NULL, 133 },
      { "include-ip-multicast-sent",      no_argument,       NULL, 134 },

      /* S h o r t  f o r m a t t i n g  o p t i o n s  (G N U) */

      { "i0",                             no_argument,       NULL, 128 },
      { "i1",                             no_argument,       NULL, 129 },
      { "i2",                             no_argument,       NULL, 130 },
      { "i3",                             no_argument,       NULL, 131 },
      { "i4",                             no_argument,       NULL, 132 },
      { "i5",                             no_argument,       NULL, 133 },
      { "i6",                             no_argument,       NULL, 134 },

      /* R o w  o p t i o n s  (G N U) */

      { "sort-by-mac-address",            no_argument,       NULL, 228 },
      { "sort-by-ip-address",             no_argument,       NULL, 229 },
      { "sort-by-hostname",               no_argument,       NULL, 230 },

      { "sort-by-pkts-all",               no_argument,       NULL, 231 },
      { "sort-by-pkts-sent",              no_argument,       NULL, 232 },
      { "sort-by-pkts-recv",              no_argument,       NULL, 233 },
      { "sort-by-broadcast-pkts-sent",    no_argument,       NULL, 234 },
      { "sort-by-multicast-pkts-sent",    no_argument,       NULL, 235 },
      { "sort-by-ip-broadcast-pkts-sent", no_argument,       NULL, 236 },
      { "sort-by-ip-multicast-pkts-sent", no_argument,       NULL, 237 },

      /* S h o r t  s o r t i n g  o p t i o n s  (G N U) */

      { "s0",                             no_argument,       NULL, 228 },
      { "s1",                             no_argument,       NULL, 229 },
      { "s2",                             no_argument,       NULL, 230 },

      { "s3",                             no_argument,       NULL, 231 },
      { "s4",                             no_argument,       NULL, 232 },
      { "s5",                             no_argument,       NULL, 233 },
      { "s6",                             no_argument,       NULL, 234 },
      { "s7",                             no_argument,       NULL, 235 },
      { "s8",                             no_argument,       NULL, 236 },
      { "s9",                             no_argument,       NULL, 237 },

      { NULL,                             0,                 NULL, 0 }
    };

  /* Local variables */

  /*  Host ID |  Total  |Tot Sent |Tot Recv |Broadcast|Multicast|IP Broad |IP Multi | */
  char * head [] =
    { argv [0],
      "Host-PlaceHolder",    "--label=Total[9]",     "--label=Tot Sent[9]",
      "--label=Tot Recv[9]", "--label=Broadcast[9]", "--label=Multicast[9]", "--label=IP Broad [9]", "--label=IP Multi [9]",
      NULL };
  char * rows [] =
    { argv [0],
      "Host-PlaceHolder",  "--total-pkts-all",      "--total-pkts-sent",
      "--total-pkts-recv", "--broadcast-pkts-sent", "--multicast-pkts-sent", "--ip-broadcast-pkts-sent", "--ip-multicast-pkts-sent",
      NULL };
  char ** a;

  int option;
  int rc = 0;
  char * name = NULL;
  interface_t * interface;

  int local = 1;                      /* by default local traffic is displayed     */
  int foreign = 1;                    /* by default remote traffic is displayed    */
  int ipless = 1;                     /* by default IP-Less hosts are displayed    */
  int unresolved = 1;                 /* by default unresolved hosts are displayed */
  int numeric = 0;                    /* by default hostnames are displayed        */

  sf * howtosort = sort_by_pkts_all;  /* default sort by # of pkts sent/recv       */
  int reverse = 0;
  int hostno = 0;

  host_t ** srchosts = NULL;          /* The hosts cache as internal maintained    */
  host_t ** host;                     /* An iterator in the previous table         */
  host_t ** dsthosts = NULL;          /* The unsorted array of pointers to hosts   */

  char ** headargv = NULL;
  char ** rowargv = NULL;

  /* Set default columns */
  a = head;
  while (a && * a)
    headargv = argsadd (headargv, * a ++);

  a = rows;
  while (a && * a)
    rowargv = argsadd (rowargv, * a ++);

  /* Parse command line options */
#define OPTSTRING "hi:nurlfpPdDx"

  optind = 0;
  optarg = NULL;
  while ((option = getopt_long (argc, argv, OPTSTRING, long_options, NULL)) != -1)
    {
      switch (option)
	{
	default:  usage (argv [0]); rc = -1; goto cleanup;

	case 'h': usage (argv [0]); goto cleanup;

	case 'i': name = optarg;    break;      /* interface name                      */
	case 'n': numeric = 1;      break;      /* display mac/ip address not hostname */
	case 'u': howtosort = NULL; break;      /* do not sort                         */
	case 'r': reverse = 1;      break;      /* reverse sort                        */
	case 'l': foreign = 0;      break;      /* include only local addresses        */
	case 'f': local = 0;        break;      /* include only foreign addresses      */
	case 'p': ipless = 0;       break;      /* exclude IP-Less hosts               */
	case 'P': ipless = 2;       break;      /* include IP-Less only hosts          */
	case 'd': unresolved = 0;   break;      /* exclude unresolved hosts            */
	case 'D': unresolved = 2;   break;      /* include unresolved only hosts       */

	case 'x':        /* exclude default formatting columns */
	  a = head;
	  while (a && * a)
	    headargv = argsrm (headargv, * a ++);

	  a = rows;
	  while (a && * a)
	    rowargv = argsrm (rowargv, * a ++);
	  break;

	case 128:
	  headargv = argsadd (headargv, "--label=Total[9]");
	  rowargv = argsadd (rowargv, "--total-pkts-all");
	  break;

	case 129:
	  headargv = argsadd (headargv, "--label=Tot Sent[9]");
	  rowargv = argsadd (rowargv, "--total-pkts-sent");
	  break;

	case 130:
	  headargv = argsadd (headargv, "--label=Tot Recv[9]");
	  rowargv = argsadd (rowargv, "--total-pkts-recv");
	  break;

	case 131:
	  headargv = argsadd (headargv, "--label=Broadcast[9]");
	  rowargv = argsadd (rowargv, "--broadcast-pkts-sent");
	  break;

	case 132:
	  headargv = argsadd (headargv, "--label=Multicast[9]");
	  rowargv = argsadd (rowargv, "--multicast-pkts-sent");
	  break;

	case 133:
	  headargv = argsadd (headargv, "--label=IP Broad [9]");
	  rowargv = argsadd (rowargv, "--ip-broadcast-pkts-sent");
	  break;

	case 134:
	  headargv = argsadd (headargv, "--label=IP Multi [9]");
	  rowargv = argsadd (rowargv, "--ip-multicast-pkts-sent");
	  break;

	case 228: howtosort = sort_by_hwaddr;            break;
	case 229: howtosort = sort_by_ip;                break;
	case 230: howtosort = sort_by_hostname;          break;

	case 231: howtosort = sort_by_pkts_all;          break;
	case 232: howtosort = sort_by_pkts_sent;         break;
	case 233: howtosort = sort_by_pkts_recv;         break;
	case 234: howtosort = sort_by_broadcast_pkts;    break;
	case 235: howtosort = sort_by_multicast_pkts;    break;
	case 236: howtosort = sort_by_ip_broadcast_pkts; break;
	case 237: howtosort = sort_by_ip_multicast_pkts; break;
	}
    }

  /* Safe to play with the 'active' interface (if any) in case no specific one was chosen by the user */
  if (! name && ! (name = getintfname ()))
    {
      printf ("%s: no interface is currently enabled for packet sniffing\n", argv [0]);
      rc = -1;
      goto cleanup;
    }

  /* Lookup for the given name in the table of enabled interfaces */
  if (! (interface = intfbyname (interfaces, name)))
    {
      printf ("%s: unknown interface %s\n", argv [0], name);
      rc = -1;
      goto cleanup;
    }

  /* Avoid to print when no information are available */
  if (interface -> status != INTERFACE_ENABLED)
    {
      printf ("%s: this interface is not currently enabled for packet sniffing\n", argv [0]);
      rc = -1;
      goto cleanup;
    }

  /* Names of hosts can be given, in which case only those entries matching the arguments will be shown */
  if (optind < argc)
    {
      while (optind < argc)
	{
	  /* Get host information via its descriptor saved into the hash tables */
	  host_t * h;
	  if (! (h = hostbykey (interface, argv [optind])))
	    printf ("%s: Unknown host\n", argv [optind]);
	  else
	    /* Put the pointer to the host into the temporary unsorted array */
	    dsthosts = hargsadd (dsthosts, h);
	  optind ++;
	}
    }
  else
    {
      /* Scan the hosts cache to display data according to user choices */
      for (srchosts = host = hostsall (interface); host && * host; host ++)
	{
	  /* Not not include id-less hosts (damn threads!) */
	  if (hostipless (* host) && ! (* host) -> hwaddress)
	    continue;

	  /* Do not include hosts with no traffic at all */
	  if (! ((* host) -> pkts_sent + (* host) -> pkts_recv))
	    continue;

	  /* Check for IP-Less hosts */
	  if ((ipless == 0 && hostipless (* host)) || (ipless == 2 && ! hostipless (* host)))
	    continue;

	  /* Check for unresolved hosts */
	  if ((unresolved == 0 && hostunresolved (* host)) || (unresolved == 2 && ! hostunresolved (* host)))
	    continue;

	  /* Check for local or remote hosts */
	  if ((local && hostlocal (* host)) || (foreign && ! hostlocal (* host)))
	    /* Put the pointer to the host into the temporary unsorted array */
	    dsthosts = hargsadd (dsthosts, * host);
	}
    }

  /* Sort and print now the hosts cache accordingly to user choices */
  if ((hostno = hargslen (dsthosts)))
    {
      int longest = hostlongest (dsthosts, numeric);
      char fmt [128];
      int i;

      /* Sort the temporary table now */
      if (numeric && howtosort == sort_by_hostname)
	howtosort = sort_by_ip;

      if (hostno && howtosort)
	qsort (dsthosts, hostno, sizeof (host_t *), howtosort);

      /* Replace the placeholder */
      sprintf (fmt, "--label=Host Id[%d]", longest);
      argsreplace (headargv, "Host-PlaceHolder", fmt);

      /* Print the table's title */
      hostprintf (NULL, argslen (headargv), headargv, COL_SEP);
      printf ("\n");

      /* Print now the hosts cache accordingly to user choices */
      for (i = 0; i < hostno; i ++)
	{
	  /* Replace the host's placeholder */
	  sprintf (fmt, numeric ? "--host-numeric=%d" : "--host-identifier=%d", longest);
	  argsreplace (rowargv, "Host-PlaceHolder", fmt);

	  hostprintf (reverse ? dsthosts [hostno - i - 1] : dsthosts [i], argslen (rowargv), rowargv, COL_SEP);
	  printf ("\n");
	}
    }

  if (srchosts)
    free (srchosts);
  if (dsthosts)
    free (dsthosts);

 cleanup:
  argsfree (rowargv);
  argsfree (headargv);

  return rc;
}
