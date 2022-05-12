/*
 * pksh - The Packet Shell
 *
 * R. Carbone (rocco@tecsiel.it)
 * 2008-2009, 2022
 *
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Display detailed info about the traffic on network interface(s)
 */


/* System headers */
#include <stdlib.h>

/* Project header */
#include "pksh.h"


/* How to use this command */
static void usage (char * cmd)
{
  printf ("`%s' sorts and displays the table of hosts currently known on a given network interface accordingly to a variety of formats and options\n", cmd);

  printf ("\n");
  printf ("Usage: %s [options] [hostname [hostname] ...]\n", cmd);

  printf ("\n");
  printf ("Examples:\n");
  printf ("   %s -i eth1                     # display the hosts cache on interface eth1 using default sorting\n", cmd);
  printf ("   %s --sort-by-mac-address -r    # display a reverse sorted table according to the MAC addresses\n", cmd);

  printf ("\n");
  printf ("Main options are:\n");
  printf ("    -h, --help                         only show this help message\n");
  printf ("    -i, --interface                    specify network interface (e.g. eth0)\n");
  printf ("    -n, --numeric                      do not resolve names\n");
  printf ("    -l, --local                        include only local hosts\n");
  printf ("    -f, --foreign                      include only remote hosts\n");
  printf ("    -p, --no-ipless                    exclude hosts that do not have an IP address\n");
  printf ("    -P, --ipless-only                  include only hosts that do not have an IP address\n");
  printf ("    -d, --exclude-unresolved           exclude hosts that do not have a symbolic address\n");
  printf ("    -D, --unresolved-only              include only hosts that do not have a symbolic address\n");

  printf ("\n");
  printf ("Display options are:\n");
  printf ("    -x, --exclude-defaults             exclude default formatting columns\n");
  printf ("  --i1, --include-xxxxxxxx             include column with xxxxxx\n");

  printf ("\n");
  printf ("Sorting options are:\n");
  printf ("    -u, --unsort                       do not sort\n");
  printf ("    -r, --reverse                      reverse the result of sorting\n");
  printf ("  --s0, --sort-by-hostname             sort the host's table by hostnames\n");
  printf ("  --s1, --sort-by-mac-address          sort the host's table by MAC addresses\n");
  printf ("  --s2, --sort-by-ip-address           sort the host's table by IP addresses\n");

  printf ("  --s3, --sort-by-xxxx                 sort the host's table by xxxxxx\n");
}


/* Show detailed information about the current traffic on a given interface */
int pksh_traffic (int argc, char * argv [])
{
  /* GNU long options */
  static struct option const long_options [] =
    {
      /* G e n e r a l  o p t i o n s  (P O S I X) */

      { "help",                               no_argument,       NULL, 'h' },
      { "interface",                          required_argument, NULL, 'i' },
      { "numeric",                            no_argument,       NULL, 'n' },
      { "unsort",                             no_argument,       NULL, 'u' },
      { "reverse",                            no_argument,       NULL, 'r' },
      { "local",                              no_argument,       NULL, 'l' },
      { "foreign",                            no_argument,       NULL, 'f' },
      { "exclude-ipless",                     no_argument,       NULL, 'p' },
      { "ipless-only",                        no_argument,       NULL, 'P' },
      { "exclude-unresolved",                 no_argument,       NULL, 'd' },
      { "unresolved-only",                    no_argument,       NULL, 'D' },
      { "exclude-defaults",                   no_argument,       NULL, 'x' },

      /* C o l u m n  o p t i o n s  (G N U) */

      { "include-mac-address",                no_argument,       NULL, 128 },

      /* S h o r t  f o r m a t t i n g  o p t i o n s  (G N U) */

      { "i1",                                 no_argument,       NULL, 128 },

      /* R o w  o p t i o n s  (G N U) */

      { "sort-by-hostname",                   no_argument,       NULL, 228 },
      { "sort-by-mac-address",                no_argument,       NULL, 229 },
      { "sort-by-ip-address",                 no_argument,       NULL, 230 },

      { "sort-by-xxxx",                       no_argument,       NULL, 231 },

      /* S h o r t  s o r t i n g  o p t i o n s  (G N U) */

      { "s0",                                 no_argument,       NULL, 228 },
      { "s1",                                 no_argument,       NULL, 229 },
      { "s2",                                 no_argument,       NULL, 230 },

      { "s3",                                 no_argument,       NULL, 231 },

      { NULL,                                 0,                 NULL, 0}
    };

  /*  Host |  xxx
  char * head [] =
    { argv [0],
      "Host-PlaceHolder", "--label=MAC Address[17]", "--label=IP[15]", "--label=Vendor[18]",
      NULL };

  char * rows [] =
    { argv [0],
      "Host-PlaceHolder", "--mac-address", "--ip-address", "--vendor-name=18",
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

  int numeric = 0;
  sf * howtosort = sort_by_hostname;  /* default sort by hostname                  */
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

	  argsrows (head);
	  a = rows;
	  while (a && * a)
	    rowargv = argsrm (rowargv, * a ++);
	  break;

	case 128:
	  headargv = argsadd (headargv, "--label=MAC Address[17]");
	  rowargv = argsadd (rowargv, "--mac-address");
	  break;

	case 129:
	  headargv = argsadd (headargv, "--label=MAC Address[17]");
	  rowargv = argsadd (rowargv, "--mac-address");
	  break;

	case 228: howtosort = sort_by_mac;      break;
	case 229: howtosort = sort_by_ip;       break;
	case 230: howtosort = sort_by_hostname; break;

	case 231: howtosort = sort_by_vendor;   break;
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
	  /* Check for multicast packets */
	  if ((* host) -> hwaddress && multicast ((* host) -> hwaddress))
	    continue;

	  /* Not not include id-less hosts (damn threads!) */
	  if (hostipless (* host) && ! (* host) -> hwaddress)
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
