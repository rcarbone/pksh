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

/* Project header */
#include "pksh.h"

/* Identifiers */
#define NAME         "pkarp"
#define BRIEF        "Tell the hosts cache and display the ARP cache on a given interface like the 'arp' command does"
#define SYNOPSIS     "pkarp [options]"
#define DESCRIPTION  "No description yet"

/* Public variable */
pksh_cmd_t cmd_arp = { NAME, BRIEF, SYNOPSIS, DESCRIPTION, pksh_pkarp };


/* GNU short options */
enum
{
  /* Startup */
  OPT_HELP               = 'h',
  OPT_QUIET              = 'q',

  OPT_INTERFACE          = 'i',
  OPT_NUMERIC            = 'n',
  OPT_UNSORT             = 'u',
  OPT_REVERSE            = 'r',
  OPT_INCLUDE_IPLESS     = 'p',
  OPT_IPLESS_ONLY        = 'P',
  OPT_EXCLUDE_UNRESOLVED = 'd',
  OPT_UNRESOLVED_ONLY    = 'D',
  OPT_EXCLUDE_DEFAULTS   = 'x',
};


/* GNU long options */
static struct option lopts [] =
{
  /* Startup */
  { "help",                        no_argument,       NULL, OPT_HELP               },
  { "quiet",                       no_argument,       NULL, OPT_QUIET              },

  /* G e n e r a l  o p t i o n s  (P O S I X) */
  { "interface",                   required_argument, NULL, OPT_INTERFACE          },
  { "numeric",                     no_argument,       NULL, OPT_NUMERIC            },
  { "unsort",                      no_argument,       NULL, OPT_UNSORT             },
  { "reverse",                     no_argument,       NULL, OPT_REVERSE            },
  { "include-ipless",              no_argument,       NULL, OPT_INCLUDE_IPLESS     },
  { "ipless-only",                 no_argument,       NULL, OPT_IPLESS_ONLY        },
  { "exclude-unresolved",          no_argument,       NULL, OPT_EXCLUDE_UNRESOLVED },
  { "unresolved-only",             no_argument,       NULL, OPT_UNRESOLVED_ONLY    },
  { "exclude-defaults",            no_argument,       NULL, OPT_EXCLUDE_DEFAULTS   },

  /* C o l u m n  o p t i o n s  (G N U) */

  { "include-mac-address",                no_argument,       NULL, 128 },
  { "include-ip-address",                 no_argument,       NULL, 129 },
  { "include-vendor-name",                no_argument,       NULL, 130 },

  /* S h o r t  f o r m a t t i n g  o p t i o n s  (G N U) */

  { "i0",                                 no_argument,       NULL, 128 },
  { "i1",                                 no_argument,       NULL, 129 },
  { "i2",                                 no_argument,       NULL, 130 },

  /* R o w  o p t i o n s  (G N U) */

  { "sort-by-mac-address",                no_argument,       NULL, 228 },
  { "sort-by-ip-address",                 no_argument,       NULL, 229 },
  { "sort-by-hostname",                   no_argument,       NULL, 230 },
  { "sort-by-vendor-name",                no_argument,       NULL, 231 },

  /* S h o r t  s o r t i n g  o p t i o n s  (G N U) */

  { "s0",                                 no_argument,       NULL, 228 },
  { "s1",                                 no_argument,       NULL, 229 },
  { "s2",                                 no_argument,       NULL, 230 },
  { "s3",                                 no_argument,       NULL, 231 },

  { NULL,                          0,                 NULL, 0 }
};


/* Display the syntax */
static void usage (char * progname, struct option * options)
{
  printf ("`%s' tell and display the ARP cache on a given interface like the 'arp' command does\n", progname);

  printf ("\n");
  printf ("Usage: %s [options] [hostname [hostname] ...]\n", progname);

  printf ("\n");
  printf ("Examples:\n");
  printf ("   %s -i eth1                   # display the ARP cache on interface eth1 using default sorting\n", progname);
  printf ("   %s --sort-by-mac-address -r  # display a reverse sorted table according to the MAC addresses\n", progname);

  printf ("\n");
  printf ("Main options are:\n");
  printf ("    -h, --help                       only show this help message\n");
  printf ("    -i, --interface                  specify network interface (e.g. eth0)\n");
  printf ("    -n, --numeric                    do not resolve names\n");
  printf ("    -p, --include-ipless             include hosts that do not have an IP address\n");
  printf ("    -P, --ipless-only                include only hosts that do not have an IP address\n");
  printf ("    -d, --exclude-unresolved         exclude hosts that do not have a symbolic address\n");
  printf ("    -D, --unresolved-only            include only hosts that do not have a symbolic address\n");
  printf ("    -v, --exclude-vendor-less        exclude hosts that do not have a vendor name resolved\n");
  printf ("    -V, --vendor-less-only           include only hosts does not have a vendor name resolved\n");

  printf ("\n");
  printf ("Display options are:\n");
  printf ("    -x, --exclude-defaults           exclude default formatting columns\n");
  printf ("  --i0, --include-mac-address        include column with MAC address\n");
  printf ("  --i1, --include-ip-address         include column with IP address\n");
  printf ("  --i2, --include-vendor             include column with Vendor Name\n");

  printf ("\n");
  printf ("Sorting options are:\n");
  printf ("    -u, --unsort                     do not sort (default sort by hostname)\n");
  printf ("    -r, --reverse                    reverse the result of sorting\n");
  printf ("  --s0, --sort-by-mac-address        sort the hosts cache by MAC addresses\n");
  printf ("  --s1, --sort-by-ip-address         sort the hosts cache by IP addresses\n");
  printf ("  --s2, --sort-by-hostname           sort the hosts cache by hostnames\n");
  printf ("  --s3, --sort-by-vendor             sort the hosts cache by Vendor Names\n");

  printf ("\n");
  printf ("This built-in also updates the $<interafce>pkhosts variable and accepts a pattern matching\n");
}


/* It queries the ARP cache like the 'arp' command does */
int pksh_pkarp (int argc, char * argv [])
{
  char * progname = basename (argv [0]);
  char * sopts    = optlegitimate (lopts);

  /* Variables that are set according to the specified options */
  bool quiet      = false;

  int option;

  /* Local variables */

  /* Host Id |   MAC Address   |            Vendor           |  Name  |  Link  | */
  char * head [] =
    { argv [0],
      "Host-PlaceHolder", "--label=MAC Address[17]", "--label=Vendor[27]", "--label=Name[6]", "--label=Link[6]",
      NULL };
  char * rows [] =
    { argv [0],
      "Host-PlaceHolder", "--mac-address", "--vendor-name=27", "--interface", "--datalink",
      NULL };
  char ** a;

  int rc = 0;
  char * name = NULL;
  interface_t * interface;

  int ipless = 0;                     /* by default IP-Less hosts are not displayed */
  int unresolved = 1;                 /* by default unresolved hosts are displayed  */
  int numeric = 0;                    /* by default hostnames are displayed         */
  int vendor = 1;                     /* by default vendor-less host are displayed  */

  sf * howtosort = sort_by_hostname;  /* default sort by hostname                   */
  int reverse = 0;
  int hostno = 0;

  host_t ** srchosts = NULL;          /* The hosts cache as internal maintained     */
  host_t ** host;                     /* An iterator in the previous table          */
  host_t ** dsthosts = NULL;          /* The unsorted array of pointers to hosts    */

  char ** headargv = NULL;
  char ** rowargv = NULL;

  /* Lookup for the command in the static table of registered extensions */
  if (! cmd_by_name (progname))
    {
      printf ("%s: Command [%s] not found.\n", progname, progname);
      return -1;
    }

  /* Set default columns */
  a = head;
  while (a && * a)
    headargv = argsmore (headargv, * a ++);

  a = rows;
  while (a && * a)
    rowargv = argsmore (rowargv, * a ++);

  /* Parse command line options */
  optind = 0;
  optarg = NULL;
  argv [0] = progname;
  while ((option = getopt_long (argc, argv, sopts, lopts, NULL)) != -1)
    {
      switch (option)
	{
	default: if (! quiet) printf ("Try '%s --help' for more information.\n", progname); rc = -1; goto cleanup;

	  /* Startup */
	case OPT_HELP:  usage (progname, lopts); goto cleanup;
	case OPT_QUIET: quiet = true;            break;

	case OPT_INTERFACE:          name = optarg;    break;      /* network interface name              */
	case OPT_NUMERIC:            numeric = 1;      break;      /* display mac/ip address not hostname */
	case OPT_UNSORT:             howtosort = NULL; break;      /* do not sort                         */
	case OPT_REVERSE:            reverse = 1;      break;      /* reverse sort                        */
	case OPT_INCLUDE_IPLESS:     ipless = 1;       break;      /* include IP-Less hosts               */
	case OPT_IPLESS_ONLY:        ipless = 2;       break;      /* include IP-Less only hosts          */
	case OPT_EXCLUDE_UNRESOLVED: unresolved = 0;   break;      /* exclude unresolved hosts            */
	case OPT_UNRESOLVED_ONLY:    unresolved = 2;   break;      /* include unresolved only hosts       */

	case OPT_EXCLUDE_DEFAULTS:        /* exclude default formatting columns */
	  a = head;
	  while (a && * a)
	    headargv = argsless (headargv, * a ++);

	  a = rows;
	  while (a && * a)
	    rowargv = argsless (rowargv, * a ++);
	  break;

	case 128:
	  headargv = argsmore (headargv, "--label=MAC Address[17]");
	  rowargv = argsmore (rowargv, "--mac-address");
	  break;

	case 129:
	  headargv = argsmore (headargv, "--label=Vendor[27]");
	  rowargv = argsmore (rowargv, "--vendor-name=27");
	  break;

	case 228: howtosort = sort_by_hwaddr;   break;
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
      /* Scan the hosts cache to display data according to user choices.
       * Include local hosts only by looking at the HW names */
      for (srchosts = host = (host_t **) htvalues (& interface -> hwnames); host && * host; host ++)
	{
	  /* Not not include id-less hosts (damn threads!) */
	  if (hostipless (* host) && ! (* host) -> hwaddress)
	    continue;

	  /* Check for IP-Less hosts */
	  if ((ipless == 0 && hostipless (* host)) || (ipless == 2 && ! hostipless (* host)))
	    continue;

	  /* Check for unresolved hosts */
	  if ((unresolved == 0 && hostunresolved (* host)) || (unresolved == 2 && ! hostunresolved (* host)))
	    continue;

	  /* Check for Vendor-Less hosts */
	  if ((vendor == 0 && ! (* host) -> vendor) || (vendor == 2 && (* host) -> vendor))
	    continue;

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
	  sprintf (fmt, numeric ? "--host-numeric=%d" : "--host-ipless=%d", longest);
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
  argsclear (rowargv);
  argsclear (headargv);

  /* Bye bye! */
  return rc;
}
