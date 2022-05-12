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
#define NAME         "services"
#define BRIEF        "Tell the hosts cache and display detailed IP protocols usage as viewed on network interface(s)"
#define SYNOPSIS     "services [options]"
#define DESCRIPTION  "No description yet"

/* Public variable */
pksh_cmd_t cmd_services = { NAME, BRIEF, SYNOPSIS, DESCRIPTION, pksh_services };


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
  OPT_LOCAL              = 'l',
  OPT_FOREIGN            = 'f',
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
  { "local",                       no_argument,       NULL, OPT_LOCAL              },
  { "foreign",                     no_argument,       NULL, OPT_FOREIGN            },
  { "include-ipless",              no_argument,       NULL, OPT_INCLUDE_IPLESS     },
  { "ipless-only",                 no_argument,       NULL, OPT_IPLESS_ONLY        },
  { "exclude-unresolved",          no_argument,       NULL, OPT_EXCLUDE_UNRESOLVED },
  { "unresolved-only",             no_argument,       NULL, OPT_UNRESOLVED_ONLY    },
  { "exclude-defaults",            no_argument,       NULL, OPT_EXCLUDE_DEFAULTS   },

  /* C o l u m n  o p t i o n s  (G N U) */

  { "include-ip-bytes-all",               no_argument,       NULL, 128 },
  { "include-http-bytes-all",             no_argument,       NULL, 129 },
  { "include-ftp-bytes-all",              no_argument,       NULL, 130 },
  { "include-dns-bytes-all",              no_argument,       NULL, 131 },
  { "include-mail-bytes-all",             no_argument,       NULL, 132 },
  { "include-ssh-bytes-all",              no_argument,       NULL, 133 },
  { "include-telnet-bytes-all",           no_argument,       NULL, 134 },
  { "include-x11-bytes-all",              no_argument,       NULL, 135 },
  { "include-nfs-bytes-all",              no_argument,       NULL, 136 },
  { "include-dhcp-bytes-all",             no_argument,       NULL, 137 },
  { "include-snmp-bytes-all",             no_argument,       NULL, 138 },
  { "include-nntp-bytes-all",             no_argument,       NULL, 139 },
  { "include-netbios-ip-bytes-all",       no_argument,       NULL, 140 },
  { "include-kazaa-bytes-all",            no_argument,       NULL, 141 },
  { "include-gnutella-bytes-all",         no_argument,       NULL, 142 },
  { "include-winmx-bytes-all",            no_argument,       NULL, 143 },
  { "include-direct-connect-bytes-all",   no_argument,       NULL, 144 },
  { "include-edonkey-bytes-all",          no_argument,       NULL, 145 },
  { "include-messenger-bytes-all",        no_argument,       NULL, 146 },
  { "include-other-ip-bytes-all",         no_argument,       NULL, 147 },

  /* S h o r t  f o r m a t t i n g  o p t i o n s  (G N U) */

  { "i1",                                 no_argument,       NULL, 128 },
  { "i2",                                 no_argument,       NULL, 129 },
  { "i3",                                 no_argument,       NULL, 130 },
  { "i4",                                 no_argument,       NULL, 131 },
  { "i5",                                 no_argument,       NULL, 132 },
  { "i6",                                 no_argument,       NULL, 133 },
  { "i7",                                 no_argument,       NULL, 134 },
  { "i8",                                 no_argument,       NULL, 135 },
  { "i9",                                 no_argument,       NULL, 136 },
  { "i10",                                no_argument,       NULL, 137 },
  { "i11",                                no_argument,       NULL, 138 },
  { "i12",                                no_argument,       NULL, 139 },
  { "i13",                                no_argument,       NULL, 140 },
  { "i14",                                no_argument,       NULL, 141 },
  { "i15",                                no_argument,       NULL, 142 },
  { "i16",                                no_argument,       NULL, 143 },
  { "i17",                                no_argument,       NULL, 144 },
  { "i18",                                no_argument,       NULL, 145 },
  { "i19",                                no_argument,       NULL, 146 },
  { "i20",                                no_argument,       NULL, 147 },

  /* R o w  o p t i o n s  (G N U) */

  { "sort-by-mac-address",                no_argument,       NULL, 228 },
  { "sort-by-ip-address",                 no_argument,       NULL, 229 },
  { "sort-by-hostname",                   no_argument,       NULL, 230 },

  { "sort-by-ip-bytes-all",               no_argument,       NULL, 231 },
  { "sort-by-http-bytes-all",             no_argument,       NULL, 232 },
  { "sort-by-ftp-bytes-all",              no_argument,       NULL, 233 },
  { "sort-by-dns-bytes-all",              no_argument,       NULL, 234 },
  { "sort-by-mail-bytes-all",             no_argument,       NULL, 235 },
  { "sort-by-ssh-bytes-all",              no_argument,       NULL, 236 },
  { "sort-by-telnet-bytes-all",           no_argument,       NULL, 237 },
  { "sort-by-netbios-ip-bytes-all",       no_argument,       NULL, 238 },
  { "sort-by-other-ip-bytes-all",         no_argument,       NULL, 239 },

  /* S h o r t  s o r t i n g  o p t i o n s  (G N U) */

  { "s0",                                 no_argument,       NULL, 228 },
  { "s1",                                 no_argument,       NULL, 229 },
  { "s2",                                 no_argument,       NULL, 230 },

  { "s3",                                 no_argument,       NULL, 231 },
  { "s4",                                 no_argument,       NULL, 232 },
  { "s5",                                 no_argument,       NULL, 233 },
  { "s6",                                 no_argument,       NULL, 234 },
  { "s7",                                 no_argument,       NULL, 235 },
  { "s8",                                 no_argument,       NULL, 236 },
  { "s9",                                 no_argument,       NULL, 237 },
  { "s10",                                no_argument,       NULL, 238 },
  { "s11",                                no_argument,       NULL, 239 },

  { NULL,                                 0,                 NULL, 0 }
};


/* Display the syntax */
static void usage (char * progname, struct option * options)
{
  printf ("`%s' provides a dynamic real-time view of the most used IP protocols on a given interface\n", progname);

  printf ("\n");
  printf ("Usage: %s [options] [hostname [hostname] ...]\n", progname);

  printf ("\n");
  printf ("Examples:\n");
  printf ("   %s -i eth1                     # display IP protocol usage viewed on interface eth1 using default sorting\n", progname);
  printf ("   %s --sort-by-mac-address -r    # display a reverse sorted table according to the MAC addresses\n", progname);

  printf ("\n");
  printf ("Main options are:\n");
  printf ("    -h, --help                             only show this help message\n");
  printf ("    -i, --interface                        specify network interface (e.g. eth0)\n");
  printf ("    -n, --numeric                          do not resolve names\n");
  printf ("    -l, --local                            include only local hosts\n");
  printf ("    -f, --foreign                          include only remote hosts\n");
  printf ("    -p, --include-ipless                   include hosts that do not have an IP address\n");
  printf ("    -P, --ipless-only                      include only hosts that do not have an IP address\n");
  printf ("    -d, --exclude-unresolved               exclude hosts that do not have a symbolic address\n");
  printf ("    -D, --unresolved-only                  include only hosts that do not have a symbolic address\n");

  printf ("\n");
  printf ("Display options are:\n");
  printf ("    -x, --exclude-defaults                 exclude default formatting columns\n");
  printf ("  --i1, --include-ip-bytes_all             include column with total IP bytes (all protocols)\n");
  printf ("  --i2, --include-http-bytes_all           include column with total HTTP bytes\n");
  printf ("  --i3, --include-ftp-bytes_all            include column with total FTP bytes\n");
  printf ("  --i4, --include-dns-bytes_all            include column with total DNS bytes\n");
  printf ("  --i5, --include-mail-bytes_all           include column with total SMTP/POP/IMAP bytes\n");
  printf ("  --i6, --include-ssh-bytes_all            include column with total SSH bytes\n");
  printf ("  --i7, --include-telnet-bytes_all         include column with total Telnet bytes\n");
  printf ("  --i8, --include-x11-bytes_all            include column with total X11 bytes\n");
  printf ("  --i9, --include-nsf-bytes_all            include column with total NFS bytes\n");
  printf (" --i10, --include-dhcp-bytes_all           include column with total DHCP bytes\n");
  printf (" --i11, --include-snmp-bytes_all           include column with total SNMP bytes\n");
  printf (" --i12, --include-nntp-bytes_all           include column with total NNTP bytes\n");
  printf (" --i13, --include-netbios-ip-bytes_all     include column with total NetBios Over IP bytes\n");
  printf (" --i14, --include-kazaa-bytes_all          include column with total Kazaa bytes\n");
  printf (" --i15, --include-gnutella-bytes_all       include column with total Gnutella bytes\n");
  printf (" --i16, --include-winmx-bytes_all          include column with total WinMX bytes\n");
  printf (" --i17, --include-direct-connect-bytes_all include column with total DirectConnect bytes\n");
  printf (" --i18, --include-edonkey-bytes_all        include column with total eDonkey bytes\n");
  printf (" --i19, --include-messenger-bytes_all      include column with total Messenger bytes\n");
  printf (" --i20, --include-other-ip-bytes_all       include column with total other IP bytes\n");

  printf ("\n");
  printf ("Sorting options are:\n");
  printf ("    -u, --unsort                           do not sort\n");
  printf ("    -r, --reverse                          reverse the result of sorting\n");
  printf ("  --s0, --sort-by-hostname                 sort the host's table by hostnames\n");
  printf ("  --s1, --sort-by-mac-address              sort the host's table by MAC addresses\n");
  printf ("  --s2, --sort-by-ip-address               sort the host's table by IP addresses\n");

  printf ("  --s3, --sort-by-ip-bytes-all             sort the host's table by total # of IP bytes sent and received\n");
  printf ("  --s4, --sort-by-http-bytes-all           sort the host's table by total # of HTTP bytes sent and received\n");
  printf ("  --s5, --sort-by-ftp-bytes-all            sort the host's table by total # of FTP bytes sent and received\n");
  printf ("  --s6, --sort-by-dns-bytes-all            sort the host's table by total # of DNS bytes sent and received\n");
  printf ("  --s7, --sort-by-mail-bytes-all           sort the host's table by total # of SMTP/POP/IMAP bytes sent and received\n");
  printf ("  --s8, --sort-by-ssh-bytes-all            sort the host's table by total # of SSH bytes sent and received\n");
  printf ("  --s9, --sort-by-telnet-bytes-all         sort the host's table by total # of Telnet bytes sent and received\n");
  printf (" --s10, --sort-by-netbios-ip-bytes-all     sort the host's table by total # of NetBios over IP bytes sent and received\n");
  printf (" --s11, --sort-by-other-ip-bytes-all       sort the host's table by total # of other IP bytes sent and received\n");
}


/* Show detailed information about the current traffic (in terms of IP protocols bytes) on a given interface */
int pksh_services (int argc, char * argv [])
{
  char * progname = basename (argv [0]);
  char * sopts    = optlegitimate (lopts);

  /* Variables that are set according to the specified options */
  bool quiet      = false;

  int option;

  /* Local variables */

  /* Host | Total IP |  HTTP   |   FTP   |   DNS   |  Mail   |   SSH   | Telnet  |  Other  | */
  char * head [] =
    { argv [0],
      "Host-PlaceHolder", "--label=Total IP[9]", "--label=HTTP[9]", "--label=FTP[9]", "--label=DNS[9]", "--label=Mail[9]",
      "--label=SSH[9]", "--label=Telnet[9]", "--label=NetBiosIP[9]", "--label=Other[9]",
      NULL };
  char * rows [] =
    { argv [0],
      "Host-PlaceHolder", "--ip-bytes-all", "--http-bytes-all", "--ftp-bytes-all", "--dns-bytes-all", "--mail-bytes-all",
      "--ssh-bytes-all", "--telnet-bytes-all", "--netbios-ip-bytes-all", "--other-ip-bytes-all",
      NULL };
  char ** a;

  int rc = 0;
  char * name = NULL;
  interface_t * interface;

  int local = 1;                         /* by default local traffic is displayed       */
  int foreign = 1;                       /* by default remote traffic is displayed      */
  int ipless = 0;                        /* by default IP-Less hosts are not displayed  */
  int unresolved = 1;                    /* by default unresolved hosts are displayed   */
  int numeric = 0;                       /* by default hostnames are displayed          */

  sf * howtosort = sort_by_ip_bytes_all; /* default sort by tot # of IP bytes sent/recv */
  int reverse = 0;
  int hostno = 0;

  host_t ** srchosts = NULL;             /* The hosts cache as internal maintained      */
  host_t ** host;                        /* An iterator in the previous table           */
  host_t ** dsthosts = NULL;             /* The unsorted array of pointers to hosts     */

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
#define OPTSTRING "hi:nurlfpPdDx"

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
	case OPT_LOCAL:              foreign = 0;      break;      /* include only local addresses        */
	case OPT_FOREIGN:            local = 0;        break;      /* include only foreign addresses      */
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
	  headargv = argsmore (headargv, "--label=Total IP[9]");
	  rowargv = argsmore (rowargv, "--ip-bytes-all");
	  break;

	case 129:
	  headargv = argsmore (headargv, "--label=HTTP[9]");
	  rowargv = argsmore (rowargv, "--http-bytes-all");
	  break;

	case 130:
	  headargv = argsmore (headargv, "--label=FTP[9]");
	  rowargv = argsmore (rowargv, "--ftp-bytes-all");
	  break;

	case 131:
	  headargv = argsmore (headargv, "--label=DNS[9]");
	  rowargv = argsmore (rowargv, "--dns-bytes-all");
	  break;

	case 132:
	  headargv = argsmore (headargv, "--label=Mail[9]");
	  rowargv = argsmore (rowargv, "--mail-bytes-all");
	  break;

	case 133:
	  headargv = argsmore (headargv, "--label=SSH[9]");
	  rowargv = argsmore (rowargv, "--ssh-bytes-all");
	  break;

	case 134:
	  headargv = argsmore (headargv, "--label=Telnet[9]");
	  rowargv = argsmore (rowargv, "--telnet-bytes-all");
	  break;

	case 135:
	  headargv = argsmore (headargv, "--label=X11[9]");
	  rowargv = argsmore (rowargv, "--x11-bytes-all");
	  break;

	case 136:
	  headargv = argsmore (headargv, "--label=NFS[9]");
	  rowargv = argsmore (rowargv, "--nfs-bytes-all");
	  break;

	case 137:
	  headargv = argsmore (headargv, "--label=DHCP/BOOTP[9]");
	  rowargv = argsmore (rowargv, "--dhcp-bytes-all");
	  break;

	case 138:
	  headargv = argsmore (headargv, "--label=SNMP[9]");
	  rowargv = argsmore (rowargv, "--snmp-bytes-all");
	  break;

	case 139:
	  headargv = argsmore (headargv, "--label=NNTP[9]");
	  rowargv = argsmore (rowargv, "--nntp-bytes-all");
	  break;

	case 140:
	  headargv = argsmore (headargv, "--label=NetBiosIP[9]");
	  rowargv = argsmore (rowargv, "--netbios-ip-bytes-all");
	  break;

	case 141:
	  headargv = argsmore (headargv, "--label=Kazaa[9]");
	  rowargv = argsmore (rowargv, "--kazaa-bytes-all");
	  break;

	case 142:
	  headargv = argsmore (headargv, "--label=Gnutella[9]");
	  rowargv = argsmore (rowargv, "--gnutella-bytes-all");
	  break;

	case 143:
	  headargv = argsmore (headargv, "--label=WinMX[9]");
	  rowargv = argsmore (rowargv, "--winmx-bytes-all");
	  break;

	case 144:
	  headargv = argsmore (headargv, "--label=DirectConn[9]");
	  rowargv = argsmore (rowargv, "--direct-connect-bytes-all");
	  break;

	case 145:
	  headargv = argsmore (headargv, "--label=eDonkey[9]");
	  rowargv = argsmore (rowargv, "--edonkey-bytes-all");
	  break;

	case 146:
	  headargv = argsmore (headargv, "--label=Messenger[9]");
	  rowargv = argsmore (rowargv, "--messenger-bytes-all");
	  break;

	case 147:
	  headargv = argsmore (headargv, "--label=Other[9]");
	  rowargv = argsmore (rowargv, "--other-ip-bytes-all");
	  break;

	case 228: howtosort = sort_by_hwaddr;               break;
	case 229: howtosort = sort_by_ip;                   break;
	case 230: howtosort = sort_by_hostname;             break;

	case 231: howtosort = sort_by_ip_bytes_all;         break;
	case 232: howtosort = sort_by_http_bytes_all;       break;
	case 233: howtosort = sort_by_ftp_bytes_all;        break;
	case 234: howtosort = sort_by_dns_bytes_all;        break;
	case 235: howtosort = sort_by_mail_bytes_all;       break;
	case 236: howtosort = sort_by_ssh_bytes_all;        break;
	case 237: howtosort = sort_by_telnet_bytes_all;     break;
	case 238: howtosort = sort_by_netbios_ip_bytes_all; break;
	case 239: howtosort = sort_by_other_ip_bytes_all;   break;
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
  argsclear (rowargv);
  argsclear (headargv);

  return rc;
}
