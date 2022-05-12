/*
 * pksh - The Packet Shell
 *
 * R. Carbone (rocco@tecsiel.it)
 * 2008-2009, 2022
 *
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 */


/* Project header */
#include "pksh.h"


/* All the commands grouped together in a static unsorted table */
static pksh_cmd_t * commands [] =
{
  /* Helpers */
  & cmd_help,
  & cmd_about,
  & cmd_version,
  & cmd_license,

  /* Network Interfaces */
  & cmd_dev,
  & cmd_open,
  & cmd_close,
  & cmd_enable,
  & cmd_status,
  & cmd_uptime,
  & cmd_filter,
  & cmd_swap,

  /* Viewers */
  & cmd_packets,
  & cmd_bytes,
  & cmd_hosts,
  & cmd_arp,
  & cmd_finger,
  & cmd_last,
  & cmd_who,
#if defined(ROCCO)
  & cmd_services,
#endif /* ROCCO */
  & cmd_throughput,

  NULL
};


/* Helpers */
unsigned cmd_size (void)
{
  return (sizeof (commands) / sizeof (commands [0])) - 1;  /* Exclude NULL terminator */
}


/* Return all command names */
char ** cmd_names (void)
{
  char ** names = NULL;
  unsigned i;
  for (i = 0; i < cmd_size (); i ++)
    names = argsmore (names, commands [i] -> name);
  return names;
}


/* Lookup for a command by name (linear search) */
pksh_cmd_t * cmd_by_name (char * name)
{
  unsigned i;
  if (name)
    for (i = 0; i < cmd_size (); i ++)
      if (commands [i] -> name && ! strcmp (name, commands [i] -> name))
	return commands [i];
  return NULL;
}


/* Lookup for a command by index */
pksh_cmd_t * cmd_lookup (unsigned i)
{
  return i < cmd_size() ? commands [i] : NULL;
}


/* Lookup for a command name by index */
char * cmd_by_index (unsigned i)
{
  return i < cmd_size () ? commands [i] -> name : NULL;
}


unsigned cmd_maxname (void)
{
  static unsigned val = 0;
  unsigned i;

  if (val)
    return val;

  for (i = 0; i < cmd_size (); i ++)
    if (commands [i] -> name)
      val = RMAX (val, strlen (commands [i] -> name));
  return val;
}
