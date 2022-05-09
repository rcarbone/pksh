/*
 * pksh - The Packet Shell
 *
 * R. Carbone (rocco@tecsiel.it)
 * 2003, 2008-2009, 2022
 *
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Provide short help messages for the extensions implemented by the Packet Shell
 */


/* Project header */
#include "pksh.h"


/* Constants */
#define HELPINDENT 10

/* The structure contains information on the commands the application can understand */
typedef struct
{
  char * name;        /* user printable name of the command */
  int implemented;    /* true if command is implemented     */
  char * help;        /* help string                        */
} command_t;


/* The table with all the commands */
static command_t table [] =
{
  { "ip",         0, "List of the IP Protocols currently monitored"},
  { "pkcal",      0, "Show host traffic for latest 24 hours on network interface(s)"},
  { "pknbt",      0, "Query the hosts cache for netbios names"},

  { "bytes",      1, "Show detailed information about traffic (in terms of bytes) on network interface(s)"},
  { "packets",    1, "Show detailed information about traffic (in terms of packets) on network interface(s)"},
  { "pkarp",      1, "Query the hosts cache and display information for given hosts like the 'arp' command does"},
  { "pkclose",    1, "Close network interface(s)"},
  { "pkdev",      1, "List network interface(s) attached to the system suitable for packet capturing"},
  { "pkdisable",  0, "Stop collecting and processing packets on network interface(s)"},
  { "pkenable",   1, "Start collecting and processing packets on network interface(s)"},
  { "pkfilter",   1, "Display/Apply a filter to the a network interface"},
  { "pkfinger",   1, "Tell the hosts cache and display information for given hosts like the 'finger' command does for users"},
  { "pkhelp",     1, "Help [command] If command is specified, print out help on it, otherwise print out the list of extensions"},
  { "pkhosts",    1, "Query the hosts cache and display a table of hosts viewed on network interface(s) sorted accordingly to a given criteria"},
  { "pklast",     1, "Query the hosts cache and display a table of hosts viewed on network interface(s) sorted accordingly to their age"},
  { "pkopen",     1, "Open network interface(s) to look at packets on the network"},
  { "pkstatus",   1, "Tell interface status information"},
  { "pkswap",     1, "Switch to interface"},
  { "pkuptime",   1, "Tell how long the Packet Shell has been running"},
  { "pkwho",      1, "Query the hosts cache and display a table of hosts viewed on network interface(s) sorted accordingly to their age"},
  { "throughput", 0, "Show detailed information about traffic (in terms of throughput) on network interface(s)"},
  { "protocols",  0, "Show protocols usage on network interface(s)"},

  { "services",   0, "Show IP protocols usage on network interface(s)"},
  { "traffic",    0, "Show network traffic information"},

  { NULL,         0, NULL }  /* EOT (End Of Table) */
};


/* Functions to implement the commands */
#define TABLESIZE sizeof (table) / sizeof (table [0])

static int longestcmd (void)
{
  command_t * cmd;
  int len = 0;
  int longest = 0;

  for (cmd = table; cmd < table + TABLESIZE; cmd ++)
    {
      len = cmd -> name ? strlen (cmd -> name) : 0;
      if (longest < len)
	longest = len;
    }
  return longest;
}


/* The `list help' command */
static void list_help_commands (void)
{
#define INCREASED 2
  command_t * command;
  int i;
  int j;
  int rows;
  int cols;
  int width;
  int max = longestcmd () + INCREASED;

  /*
   * width is a multiple of 8
   *
   * it is increased of 2 to show commands
   * not yet tested enclosed between _..._
   */
  width = (max + INCREASED + 8) &~ 7;
  cols = 80 / width;
  if (cols == 0)
    cols = 1;
  rows = (TABLESIZE + cols - 1) / cols;

  printf ("the following built-ins, as extensions to the tcsh commands, are available:\n");
  printf ("[commands enclosed in '_..._' are not implemented or they are still in alpha stage]\n\n");

  for (i = 0; i < rows; i ++)
    {
      for (j = 0; j < cols; j ++)
	{
	  command = table + i * cols + j;

	  if (command -> name && i * cols + j < TABLESIZE)
	    if (command -> implemented)
	      printf (" %-*.*s ", max + 1, max + 1, command -> name);
	    else
	      printf ("_%s_%*c ", command -> name, (int) (max - strlen (command -> name)), ' ');
	  else
	    break;
	}
      printf ("\n");
    }
}


/*
 * Look up NAME as the name of a command, and return
 * a pointer to that command.
 * Return a NULL pointer if NAME isn't a command name.
 */
static command_t * lookup (char * name)
{
  char * p;
  char * q;
  command_t * command;
  command_t * found;

  int nmatches = 0;
  int longest = 0;

  found = (command_t *) NULL;
  for (command = table; (p = command -> name); command ++)
    {
      for (q = name; * q == * p ++; q ++)
	if (* q == 0)		/* exact match ? */
	  return command;
      if (! * q)
	{			/* the name was a prefix */
	  if ((q - name) > longest)
	    {
	      longest = q - name;
	      nmatches = 1;
	      found = command;
	    }
	  else if (q - name == longest)
	    nmatches ++;
	}
    }

  switch (nmatches)
    {
    case 0:
      return (command_t *) NULL;
    case 1:
      return (command_t *) -1;
    default:
      return found;
    }
}


/* The `help' function */
int pksh_pkhelp (int argc, char * argv [])
{
  command_t * command;

  if (argc == 1)
    {
      list_help_commands ();
      return 0;
    }

  while (-- argc)
    {
      command = lookup (argv [argc]);
      if (command == (command_t *) -1)
	{
	  printf ("Command (%s) : ambiguous help\n", argv [argc]);
	  continue;
	}
      else if (command == (command_t *) 0)
	{
	  printf ("command_t (%s) : invalid help\n", argv [argc]);
	  continue;
	}
      else
	printf ("%-*s\t%s\n", HELPINDENT, command -> name, command -> help);
    }
  return 0;
}
