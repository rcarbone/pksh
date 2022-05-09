/*
 * pksh - The Packet Shell
 *
 * R. Carbone (rocco@tecsiel.it)
 * 2003, 2008-2009, 2022
 *
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Routines to handle the internal hosts cache
 *   Heavily based on:
 *     "Simple hash table implementation"
 *     "Simple doubly-linked list implementation"
 *   by Michael W. Shaffer <mwshaffer@yahoo.com>
 *
 *   with few enhanchements by me, Rocco
 */


/* System headers */
#include <stdlib.h>

/* Project header */
#include "pksh.h"


/* Allocate a new host on the given interface */
static host_t * mkhost (interface_t * intf)
{
  host_t * h = calloc (sizeof (host_t), 1);
  if (! h)
    return NULL;

  gettimeofday (& h -> first, NULL);
  gettimeofday (& h -> last, NULL);

  h -> intf = intf;
  h -> ttl_shortest = 256;  /* This allow to correctly calculate its minimum value */

  return h;
}


/* How many items are in a the NULL terminated table? */
int hargslen (host_t * argv [])
{
  int argc = 0; while (argv && * argv ++) argc ++; return argc;
}


/* Add an element to the table of arguments */
host_t ** hargsadd (host_t * argv [], host_t * h)
{
  int argc = hargslen (argv);
  if (h)
    {
      /* buy memory */
      if (! (argv = realloc (argv, (1 + argc + 1) * sizeof (h))))
	return (NULL);
      argv [argc ++] = h;
      argv [argc]    = NULL;        /* do the table NULL terminated */
    }

  return argv;
}


/* Return all the pointers to the hosts maintained into the internal hash tables */
host_t ** hostsall (interface_t * intf)
{
  /* Almost all the hosts are kept in the 'ipnames' hash table */
  host_t ** hosts = (host_t **) htvalues (& intf -> ipnames);

  /* To complete the list I have to put all the IP-less equipment of the local subnet */
  host_t ** hw = (host_t **) htvalues (& intf -> hwnames);

  while (hw && * hw)
    {
      if (hostipless (* hw))
	hosts = hargsadd (hosts, * hw);
      hw ++;
    }

  return hosts;
}


/* Return all the known host identifiers (a concatenation of 'hwname', 'ipnames', 'hostnames') */
char ** hostskeys (interface_t * intf)
{
  char ** a;
  char ** b;
  char ** keys = argscat (argscat (htkeys (& intf -> hwnames), a = htkeys (& intf -> ipnames)), b = htkeys (& intf -> hostnames));

  argsclear (a);
  argsclear (b);

  return keys;
}


/* Return the # of hosts on the local subnet */
int hostnolocal (host_t * hosts [])
{
  int argc = 0;
  while (hosts && * hosts)
    if ((* hosts ++) -> hwaddress)
      argc ++;

  return argc;
}


/* Return the # of hosts not on the local subnet */
int hostnoforeign (host_t * hosts [])
{
  int argc = 0;
  while (hosts && * hosts)
    {
      if (! (* hosts) -> hwaddress && (* hosts) -> ipaddr)
	argc ++;
      hosts ++;
    }

  return argc;
}


/* Lookup for a key into the hash table 't' and return its content (that is a pointer to host_t) */
static host_t * hostlookup (char * k, struct hash_table * t)
{
  struct datum pair;
  struct datum * h;

  pair . key   = k;
  pair . ksize = strlen (k);

  return (h = hash_table_search (t, & pair)) ? (host_t *) h -> val : NULL;
}


/* Lookup a host by its unique identifier into the internal hash tables */
host_t * hostbykey (interface_t * intf, char * k)
{
  host_t * h;
  return (h = hostlookup (k, & intf -> hwnames)) || (h = hostlookup (k, & intf -> ipnames)) || (h = hostlookup (k, & intf -> hostnames)) ? h : NULL; 
}


/* Insert an item (key => pointer to host_t) into the hash table 't' */
static host_t * htadd (interface_t * intf, char * key, struct hash_table * t)
{
  struct datum pair;
  host_t * h;

  /* Lookup if the name is already known */
  if ((h = hostlookup (key, t)))
    {
      /* Already in, then set the time it was last seen */
      gettimeofday (& h -> last, NULL);
      return h;
    }

  /* The key */
  pair . key   = strdup (key);
  pair . ksize = strlen (key);

  /* The value is a pointer to a new allocated host_t */
  h = pair . val = mkhost (intf);
  pair . vsize   = sizeof (host_t);

  /* Insert only the key into the table and a reference to the object */
  hash_table_refer (t, & pair);

  return h;
}


/* Bind an item (key => reference to host_t) into the hash table 't' */
static host_t * htbind (char * key, host_t * ref, struct hash_table * t)
{
  struct datum pair;
  host_t * h;

  if (! key)
    return NULL;

  /* Lookup if the name is already known */
  if ((h = hostlookup (key, t)))
    {
      /* Already in, then set the time it was last seen */
      gettimeofday (& h -> last, NULL);
      return h;
    }

  /* The key */
  pair . key   = strdup (key);
  pair . ksize = strlen (key);

  /* The value is a pointer to an already existing object host_t referenced by 'ref' */
  pair . val   = ref;
  pair . vsize = sizeof (host_t);

  /* Insert the only the key into the table and the reference to the object */
  hash_table_refer (t, & pair);

  return ref;
}


/* Add a HW address to the hash table of knows names (if not already in) */
host_t * addtohwnames (interface_t * intf, char * key)
{
  return htadd (intf, key, & intf -> hwnames);
}


/* Add an IP address to the hash table of knows address (if not already in) */
host_t * addtoipnames (interface_t * intf, char * key)
{
  return strcmp (key, NULL_IPADDR) ? htadd (intf, key, & intf -> ipnames) : NULL;
}


/* Bind an IP address to an already allocated object passed by reference 'h' (if not already bound) */
host_t * bindtoipnames (interface_t * intf, char * ipaddr, host_t * h)
{
  return htbind (ipaddr, h, & intf -> ipnames);
}


/* Bind a hostname to an already allocated object passed by reference 'h' (if not already bound) */
host_t * bindtohostnames (interface_t * intf, char * hostname, host_t * h)
{
  return htbind (hostname, h, & intf -> hostnames);
}
