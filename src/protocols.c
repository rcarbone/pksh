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
#define NAME         "protocols"
#define BRIEF        "Tell the hosts cache and display detailed protocols usage as viewed on network interface(s)"
#define SYNOPSIS     "protocols [options]"
#define DESCRIPTION  "No description yet"

/* Public variable */
pksh_cmd_t cmd_protocols = { NAME, BRIEF, SYNOPSIS, DESCRIPTION, pksh_protocols };


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

  /* C o l u m n s  o p t i o n s  (G N U) */

  { "include-total",                     no_argument,       NULL, 128 },
  { "include-ip",                        no_argument,       NULL, 129 },
  { "include-tcp",                       no_argument,       NULL, 130 },
  { "include-udp",                       no_argument,       NULL, 131 },
  { "include-icmp",                      no_argument,       NULL, 132 },
  { "include-other-ip",                  no_argument,       NULL, 133 },

  { "include-ip-broadcast",              no_argument,       NULL, 134 },
  { "include-ip-multicast",              no_argument,       NULL, 135 },

  /* S h o r t  f o r m a t t i n g  o p t i o n s  (G N U) */

  { "i0",                                no_argument,       NULL, 128 },
  { "i1",                                no_argument,       NULL, 129 },
  { "i2",                                no_argument,       NULL, 130 },
  { "i3",                                no_argument,       NULL, 131 },
  { "i4",                                no_argument,       NULL, 132 },
  { "i5",                                no_argument,       NULL, 133 },
  { "i6",                                no_argument,       NULL, 134 },
  { "i7",                                no_argument,       NULL, 135 },

  /* R o w  o p t i o n s  (G N U) */

  { "sort-by-mac-address",               no_argument,       NULL, 228 },
  { "sort-by-ip-address",                no_argument,       NULL, 229 },
  { "sort-by-hostname",                  no_argument,       NULL, 230 },

  { "sort-by-bytes-all",                 no_argument,       NULL, 231 },
  { "sort-by-ip-bytes-all",              no_argument,       NULL, 232 },
  { "sort-by-ip-broadcast-bytes",        no_argument,       NULL, 233 },
  { "sort-by-ip-multicast-bytes",        no_argument,       NULL, 234 },
  { "sort-by-tcp-bytes-all",             no_argument,       NULL, 235 },
  { "sort-by-udp-bytes-all",             no_argument,       NULL, 236 },
  { "sort-by-icmp-bytes-all",            no_argument,       NULL, 237 },
  { "sort-by-other-ip-bytes-all",        no_argument,       NULL, 238 },

  { "sort-by-packets-all",               no_argument,       NULL, 239 },
  { "sort-by-ip-packets-all",            no_argument,       NULL, 240 },
  { "sort-by-ip-broadcast-packets",      no_argument,       NULL, 241 },
  { "sort-by-ip-multicast-packets",      no_argument,       NULL, 242 },
  { "sort-by-tcp-packets-all",           no_argument,       NULL, 243 },
  { "sort-by-udp-packets-all",           no_argument,       NULL, 244 },
  { "sort-by-icmp-packets-all",          no_argument,       NULL, 245 },
  { "sort-by-other-ip-packets-all",      no_argument,       NULL, 246 },

  { "sort-by-bytes-sent",                no_argument,       NULL, 247 },
  { "sort-by-ip-bytes-sent",             no_argument,       NULL, 248 },
  { "sort-by-tcp-bytes-sent",            no_argument,       NULL, 249 },
  { "sort-by-udp-bytes-sent",            no_argument,       NULL, 250 },
  { "sort-by-icmp-bytes-sent",           no_argument,       NULL, 251 },
  { "sort-by-other-ip-bytes-sent",       no_argument,       NULL, 252 },

  { "sort-by-bytes-recv",                no_argument,       NULL, 253 },
  { "sort-by-ip-bytes-recv",             no_argument,       NULL, 254 },
  { "sort-by-tcp-bytes-recv",            no_argument,       NULL, 255 },
  { "sort-by-udp-bytes-recv",            no_argument,       NULL, 256 },
  { "sort-by-icmp-bytes-recv",           no_argument,       NULL, 257 },
  { "sort-by-other-ip-bytes-recv",       no_argument,       NULL, 258 },

  { "sort-by-pkts-sent",                 no_argument,       NULL, 259 },
  { "sort-by-ip-pkts-sent",              no_argument,       NULL, 260 },
  { "sort-by-tcp-pkts-sent",             no_argument,       NULL, 261 },
  { "sort-by-udp-pkts-sent",             no_argument,       NULL, 262 },
  { "sort-by-icmp-pkts-sent",            no_argument,       NULL, 263 },
  { "sort-by-other-ip-pkts-sent",        no_argument,       NULL, 264 },

  { "sort-by-pkts-recv",                 no_argument,       NULL, 265 },
  { "sort-by-ip-pkts-recv",              no_argument,       NULL, 266 },
  { "sort-by-tcp-pkts-recv",             no_argument,       NULL, 267 },
  { "sort-by-udp-pkts-recv",             no_argument,       NULL, 268 },
  { "sort-by-icmp-pkts-recv",            no_argument,       NULL, 269 },
  { "sort-by-other-ip-pkts-recv",        no_argument,       NULL, 270 },

  /* S h o r t  s o r t i n g  o p t i o n s  (G N U) */

  { "s0",                                no_argument,       NULL, 228 },
  { "s1",                                no_argument,       NULL, 229 },
  { "s2",                                no_argument,       NULL, 230 },

  { "s3",                                no_argument,       NULL, 231 },
  { "s4",                                no_argument,       NULL, 232 },
  { "s5",                                no_argument,       NULL, 233 },
  { "s6",                                no_argument,       NULL, 234 },
  { "s7",                                no_argument,       NULL, 235 },
  { "s8",                                no_argument,       NULL, 236 },
  { "s9",                                no_argument,       NULL, 237 },
  { "s10",                               no_argument,       NULL, 238 },

  { "s11",                               no_argument,       NULL, 239 },
  { "s12",                               no_argument,       NULL, 240 },
  { "s13",                               no_argument,       NULL, 241 },
  { "s14",                               no_argument,       NULL, 242 },
  { "s15",                               no_argument,       NULL, 243 },
  { "s16",                               no_argument,       NULL, 244 },
  { "s17",                               no_argument,       NULL, 245 },
  { "s18",                               no_argument,       NULL, 246 },

  { "s19",                               no_argument,       NULL, 247 },
  { "s20",                               no_argument,       NULL, 248 },
  { "s21",                               no_argument,       NULL, 249 },
  { "s22",                               no_argument,       NULL, 250 },
  { "s23",                               no_argument,       NULL, 251 },
  { "s24",                               no_argument,       NULL, 252 },

  { "s25",                               no_argument,       NULL, 253 },
  { "s26",                               no_argument,       NULL, 254 },
  { "s27",                               no_argument,       NULL, 255 },
  { "s28",                               no_argument,       NULL, 256 },
  { "s29",                               no_argument,       NULL, 257 },
  { "s30",                               no_argument,       NULL, 258 },

  { "s31",                               no_argument,       NULL, 259 },
  { "s32",                               no_argument,       NULL, 260 },
  { "s33",                               no_argument,       NULL, 261 },
  { "s34",                               no_argument,       NULL, 262 },
  { "s35",                               no_argument,       NULL, 263 },
  { "s36",                               no_argument,       NULL, 264 },

  { "s37",                               no_argument,       NULL, 265 },
  { "s38",                               no_argument,       NULL, 266 },
  { "s39",                               no_argument,       NULL, 267 },
  { "s40",                               no_argument,       NULL, 268 },
  { "s41",                               no_argument,       NULL, 269 },
  { "s42",                               no_argument,       NULL, 270 },

  { NULL,                          0,                 NULL, 0 }
};


/* Display the syntax */
static void usage (char * progname, struct option * options)
{
  printf ("`%s' provides a dynamic real-time view of the most used protocols on a given interface\n", progname);

  printf ("\n");
  printf ("Usage: %s [options] [hostname [hostname] ...]\n", progname);

  printf ("\n");
  printf ("Examples:\n");
  printf ("   %s -i eth1                     # display protocol usage viewed on interface eth1 using default sorting\n", progname);
  printf ("   %s --sort-by-mac-address -r    # display a reverse sorted table according to the MAC addresses\n", progname);

  printf ("\n");
  printf ("Main options are:\n");
  printf ("    -h, --help                              only show this help message\n");
  printf ("    -i, --interface                         specify network interface (e.g. eth0)\n");
  printf ("    -n, --numeric                           do not resolve names\n");
  printf ("    -l, --local                             include only local hosts\n");
  printf ("    -f, --foreign                           include only remote hosts\n");
  printf ("    -p, --include-ipless                    include hosts that do not have an IP address\n");
  printf ("    -P, --ipless-only                       include only hosts that do not have an IP address\n");
  printf ("    -d, --exclude-unresolved                exclude hosts that do not have a symbolic address\n");
  printf ("    -D, --unresolved-only                   include only hosts that do not have a symbolic address\n");

  printf ("\n");
  printf ("Display options are:\n");
  printf ("    -x, --exclude-defaults                  exclude default formatting columns\n");
  printf ("  --i0, --include-total                     include column with total bytes (all protocols)\n");
  printf ("  --i1, --include-ip                        include column with IP bytes\n");
  printf ("  --i2, --include-tcp                       include column with TCP bytes\n");
  printf ("  --i3, --include-udp                       include column with UDP bytes\n");
  printf ("  --i4, --include-icmp                      include column with ICMP bytes\n");
  printf ("  --i5, --include-other-ip                  include column with Other-IP bytes\n");
  printf ("  --i6, --include-ip-broadcast              include column with # of IP broadcast bytes\n");
  printf ("  --i7, --include-ip-multicast              include column with # of IP multicast bytes\n");
#if defined(FIXME)
  printf ("  --i8, --include-appletalk                 include column with Appletalk bytes\n");
  printf ("  --i9, --include-decnet                    include column with Decnet bytes\n");
  printf (" --i10, --include-dlc                       include column with DLC bytes\n");
  printf (" --i11, --include-ipv6                      include column with IPv6 bytes\n");
  printf (" --i12, --include-ipx                       include column with IPX bytes\n");
  printf (" --i13, --include-netbios                   include column with NetBios bytes\n");
  printf (" --i14, --include-osi                       include column with OSI bytes\n");
  printf (" --i15, --include-rarp                      include column with (R)ARP bytes\n");
  printf (" --i16, --include-stp                       include column with STP bytes\n");
#endif /* FIXME */

  printf ("\n");
  printf ("Sorting options are:\n");
  printf ("    -u, --unsort                            do not sort (default sort by tot # of bytes sent and received\n");
  printf ("    -r, --reverse                           reverse the result of sorting\n");
  printf ("  --s0, --sort-by-mac-address               sort the hosts cache by MAC addresses\n");
  printf ("  --s1, --sort-by-ip-address                sort the hosts cache by IP addresses\n");
  printf ("  --s2, --sort-by-hostname                  sort the hosts cache by hostnames\n");

  printf ("  --s3, --sort-by-bytes-all                 sort the hosts cache by total # of bytes sent and received\n");
  printf ("  --s4, --sort-by-ip-bytes-all              sort the hosts cache by total # of IP bytes sent and received\n");
  printf ("  --s5, --sort-by-ip-broadcast-bytes        sort the hosts cache by total # of broadcast bytes sent\n");
  printf ("  --s6, --sort-by-ip-multicast-bytes        sort the hosts cache by total # of multicast bytes sent\n");
  printf ("  --s7, --sort-by-tcp-bytes-all             sort the hosts cache by total # of TCP bytes sent and received\n");
  printf ("  --s8, --sort-by-udp-bytes-all             sort the hosts cache by total # of UDP bytes sent and received\n");
  printf ("  --s9, --sort-by-icmp-bytes-all            sort the hosts cache by total # of ICMP bytes sent and received\n");
  printf (" --s10, --sort-by-other-ip-bytes-all        sort the hosts cache by total # of Other-IP bytes sent and received\n");

  printf (" --s11, --sort-by-packets-all               sort the hosts cache by total # of packets sent and received\n");
  printf (" --s12, --sort-by-ip-broadcast-packets      sort the hosts cache by total # of broadcast packets sent\n");
  printf (" --s13, --sort-by-ip-multicast-packets      sort the hosts cache by total # of multicast packets sent\n");
  printf (" --s14, --sort-by-ip-packets-all            sort the hosts cache by total # of IP packets sent and received\n");
  printf (" --s15, --sort-by-tcp-packets-all           sort the hosts cache by total # of TCP packets sent and received\n");
  printf (" --s16, --sort-by-udp-packets-all           sort the hosts cache by total # of UDP packets sent and received\n");
  printf (" --s17, --sort-by-icmp-packets-all          sort the hosts cache by total # of ICMP packets sent and received\n");
  printf (" --s18, --sort-by-other-ip-packets-all      sort the hosts cache by total # of Other-IP packets sent and received\n");

  printf (" --s19, --sort-by-bytes-sent                sort the hosts cache by total # of bytes sent\n");
  printf (" --s20, --sort-by-ip-bytes-sent             sort the hosts cache by total # of IP bytes sent\n");
  printf (" --s21, --sort-by-tcp-bytes-sent            sort the hosts cache by total # of TCP bytes sent\n");
  printf (" --s22, --sort-by-udp-bytes-sent            sort the hosts cache by total # of UDP bytes sent\n");
  printf (" --s23, --sort-by-icmp-bytes-sent           sort the hosts cache by total # of ICMP bytes sent\n");
  printf (" --s24, --sort-by-other-ip-bytes-sent       sort the hosts cache by total # of Other-IP bytes sent\n");

  printf (" --s25, --sort-by-bytes-received            sort the hosts cache by total # of bytes received\n");
  printf (" --s26, --sort-by-ip-bytes-received         sort the hosts cache by total # of IP bytes received\n");
  printf (" --s27, --sort-by-tcp-bytes-received        sort the hosts cache by total # of TCP bytes received\n");
  printf (" --s28, --sort-by-udp-bytes-received        sort the hosts cache by total # of UDP bytes received\n");
  printf (" --s29, --sort-by-icmp-bytes-received       sort the hosts cache by total # of ICMP bytes received\n");
  printf (" --s30, --sort-by-other-ip-bytes-received   sort the hosts cache by total # of Other-IP bytes received\n");

  printf (" --s31, --sort-by-packets-sent              sort the hosts cache by total # of packets sent\n");
  printf (" --s32, --sort-by-ip-packets-sent           sort the hosts cache by total # of IP packets sent\n");
  printf (" --s33, --sort-by-tcp-packets-sent          sort the hosts cache by total # of TCP packets sent\n");
  printf (" --s34, --sort-by-udp-packets-srnt          sort the hosts cache by total # of UDP packets sent\n");
  printf (" --s35, --sort-by-icmp-packets-sent         sort the hosts cache by total # of ICMP packets sent\n");
  printf (" --s36, --sort-by-other-ip-packets-sent     sort the hosts cache by total # of Other-IP packets sent\n");

  printf (" --s37, --sort-by-packets-received          sort the hosts cache by total # of packets received\n");
  printf (" --s38, --sort-by-ip-packets-received       sort the hosts cache by total # of IP packets received\n");
  printf (" --s39, --sort-by-tcp-packets-received      sort the hosts cache by total # of TCP packets received\n");
  printf (" --s40, --sort-by-udp-packets-received      sort the hosts cache by total # of UDP packets received\n");
  printf (" --s41, --sort-by-icmp-packets-received     sort the hosts cache by total # of ICMP packets received\n");
  printf (" --s42, --sort-by-other-ip-packets-received sort the hosts cache by total # of Other-IP packets received\n");
}


/* Show detailed information about the current traffic (in terms of protocol bytes) on a given interface */
int pksh_protocols (int argc, char * argv [])
{
  char * progname = basename (argv [0]);
  char * sopts    = optlegitimate (lopts);

  /* Variables that are set according to the specified options */
  bool quiet      = false;

  int option;

  /* Local variables */

  /* Host |  Total  |   IP    |   TCP   |   UDP   |  ICMP   | Other-IP |Broadcast|Multicast| */
  char * head [] =
    { argv [0],
      "Host-PlaceHolder", "--label=Total[9]", "--label=IP[9]", "--label=TCP[9]", "--label=UDP[9]", "--label=ICMP[9]", "--label=Other-Ip[9]",
      "--label=Broadcast[9]", "--label=Multicast[9]",
      NULL };
  char * rows [] =
    { argv [0],
      "Host-PlaceHolder", "--total-bytes-all", "--ip-bytes-all", "--tcp-bytes-all", "--udp-bytes-all", "--icmp-bytes-all", "--other-ip-bytes-all",
      "--ip-broadcast-bytes", "--ip-multicast-bytes",
      NULL };
  char ** a;

  int rc = 0;
  char * name = NULL;
  interface_t * interface;

  int local = 1;                      /* by default local traffic is displayed      */
  int foreign = 1;                    /* by default remote traffic is displayed     */
  int ipless = 0;                     /* by default IP-Less hosts are not displayed */
  int unresolved = 1;                 /* by default unresolved hosts are displayed  */
  int numeric = 0;                    /* by default hostnames are displayed         */

  sf * howtosort = sort_by_bytes_all; /* default sort by tot # of bytes sent/recv   */
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

	  argsrows (head);
	  a = rows;
	  while (a && * a)
	    rowargv = argsless (rowargv, * a ++);
	  break;

	case 128:
	  headargv = argsmore (headargv, "--label=Total[9]");
	  rowargv = argsmore (rowargv, "--total-bytes-all");
	  break;

	case 129:
	  headargv = argsmore (headargv, "--label=IP[9]");
	  rowargv = argsmore (rowargv, "--ip-bytes-all");
	  break;

	case 130:
	  headargv = argsmore (headargv, "--label=TCP[9]");
	  rowargv = argsmore (rowargv, "--tcp-bytes-all");
	  break;

	case 131:
	  headargv = argsmore (headargv, "--label=UDP[9]");
	  rowargv = argsmore (rowargv, "--udp-bytes-all");
	  break;

	case 132:
	  headargv = argsmore (headargv, "--label=ICMP[9]");
	  rowargv = argsmore (rowargv, "--icmp-bytes-all");
	  break;

	case 133:
	  headargv = argsmore (headargv, "--label=Other-IP[9]");
	  rowargv = argsmore (rowargv, "--other-ip-bytes-all");
	  break;

	case 134:
	  headargv = argsmore (headargv, "--label=Broadcast[9]");
	  rowargv = argsmore (rowargv, "--broadcast-bytes-sent");
	  break;

	case 135:
	  headargv = argsmore (headargv, "--label=Multicast[9]");
	  rowargv = argsmore (rowargv, "--multicast-bytes");
	  break;

#if defined(FIXME)
	case 136:
	  headargv = argsmore (headargv, "--label=AppleTalk[9]");
	  rowargv = argsmore (rowargv, "--appletalk-bytes-all");
	  break;

	case 137:
	  headargv = argsmore (headargv, "--label=Decnet[9]");
	  rowargv = argsmore (rowargv, "--decnet-bytes-all");
	  break;

	case 138:
	  headargv = argsmore (headargv, "--label=DLC[9]");
	  rowargv = argsmore (rowargv, "--dlc-bytes-all");
	  break;

	case 139:
	  headargv = argsmore (headargv, "--label=IPv6[9]");
	  rowargv = argsmore (rowargv, "--ipv6-bytes-all");
	  break;

	case 140:
	  headargv = argsmore (headargv, "--label=IPX[9]");
	  rowargv = argsmore (rowargv, "--ipx-bytes-all");
	  break;

	case 141:
	  headargv = argsmore (headargv, "--label=NetBios[9]");
	  rowargv = argsmore (rowargv, "--netbios-bytes-all");
	  break;

	case 142:
	  headargv = argsmore (headargv, "--label=OSI[9]");
	  rowargv = argsmore (rowargv, "--osi-bytes-all");
	  break;

	case 143:
	  headargv = argsmore (headargv, "--label=(R)ARP[9]");
	  rowargv = argsmore (rowargv, "--rarp-bytes-all");
	  break;

	case 144:
	  headargv = argsmore (headargv, "--label=STP[9]");
	  rowargv = argsmore (rowargv, "--stp-bytes-all");
	  break;
#endif /* FIXME */

	case 228: howtosort = sort_by_hwaddr;              break;
	case 229: howtosort = sort_by_ip;                  break;
	case 230: howtosort = sort_by_hostname;            break;

	case 231: howtosort = sort_by_bytes_all;           break;
	case 232: howtosort = sort_by_ip_bytes_all;        break;
	case 233: howtosort = sort_by_ip_broadcast_bytes;  break;
	case 234: howtosort = sort_by_ip_multicast_bytes;  break;
	case 235: howtosort = sort_by_tcp_bytes_all;       break;
	case 236: howtosort = sort_by_udp_bytes_all;       break;
	case 237: howtosort = sort_by_icmp_bytes_all;      break;
	case 238: howtosort = sort_by_other_ip_bytes_all;  break;

	case 239: howtosort = sort_by_pkts_all;            break;
	case 240: howtosort = sort_by_ip_pkts_all;         break;
	case 241: howtosort = sort_by_ip_broadcast_pkts;   break;
	case 242: howtosort = sort_by_ip_multicast_pkts;   break;
	case 243: howtosort = sort_by_tcp_pkts_all;        break;
	case 244: howtosort = sort_by_udp_pkts_all;        break;
	case 245: howtosort = sort_by_icmp_pkts_all;       break;
	case 246: howtosort = sort_by_other_ip_pkts_all;   break;

	case 247: howtosort = sort_by_bytes_sent;          break;
	case 248: howtosort = sort_by_ip_bytes_sent;       break;
	case 249: howtosort = sort_by_tcp_bytes_sent;      break;
	case 250: howtosort = sort_by_udp_bytes_sent;      break;
	case 251: howtosort = sort_by_icmp_bytes_sent;     break;
	case 252: howtosort = sort_by_other_ip_bytes_sent; break;

	case 253: howtosort = sort_by_bytes_recv;          break;
	case 254: howtosort = sort_by_ip_bytes_recv;       break;
	case 255: howtosort = sort_by_tcp_bytes_recv;      break;
	case 256: howtosort = sort_by_udp_bytes_recv;      break;
	case 257: howtosort = sort_by_icmp_bytes_recv;     break;
	case 258: howtosort = sort_by_other_ip_bytes_recv; break;

	case 259: howtosort = sort_by_pkts_sent;           break;
	case 260: howtosort = sort_by_ip_pkts_sent;        break;
	case 261: howtosort = sort_by_tcp_pkts_sent;       break;
	case 262: howtosort = sort_by_udp_pkts_sent;       break;
	case 263: howtosort = sort_by_icmp_pkts_sent;      break;
	case 264: howtosort = sort_by_other_ip_pkts_sent;  break;

	case 265: howtosort = sort_by_pkts_recv;           break;
	case 266: howtosort = sort_by_ip_pkts_recv;        break;
	case 267: howtosort = sort_by_tcp_pkts_recv;       break;
	case 268: howtosort = sort_by_udp_pkts_recv;       break;
	case 269: howtosort = sort_by_icmp_pkts_recv;      break;
	case 270: howtosort = sort_by_other_ip_pkts_recv;  break;
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

  /* Bye bye! */
  return rc;
}
