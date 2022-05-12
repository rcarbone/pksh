/*
 * pksh - The Packet Shell
 *
 * R. Carbone (rocco@tecsiel.it)
 * 2008-2009, 2022
 *
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Load and access the IEEE vendor table into
 * memory to resolve NIC vendor names at run-time
 *
 * Heavily based on:
 *   "Simple hash table implementation"
 *   "Simple doubly-linked list implementation"
 * by Michael W. Shaffer <mwshaffer@yahoo.com>
 *
 * with few enanchements by me, Rocco
 */


/* System headers */
#include <stdio.h>

/* Project header */
#include "hash.h"
#include "nic.h"


/* initial hash table size for vendor names */
#define DEFAULT_VENDOR_SIZE 1024


/* The NIC vendor table */
static struct hash_table vt;


/* Insert an element (key, value) into the hash table */
static void insert (char * k, char * v, struct hash_table * t)
{
  struct datum pair;

  /* The key is the nic prefix and the value is the vendor company name */
  pair . key   = k;
  pair . ksize = strlen (k);
  pair . val   = v;
  pair . vsize = strlen (v);

  /* Add a reference to the item into the table */
  hash_table_refer (t, & pair);
}


/* Lookup for the value associated to a given key into the hash table */
static char * lookup (char * k, struct hash_table * t)
{
  struct datum pair;
  struct datum * found;

  pair . key   = k;
  pair . ksize = strlen (k);

  return (found = hash_table_search (t, & pair)) ? found -> val : NULL;
}


/* Initialize the vendor hash table */
void vtfill (void)
{
  vendor_t * v = vendors;

  /* Initialize the hash table */
  vt . size = DEFAULT_VENDOR_SIZE;
  hash_table_init (& vt);

  while (v && v -> prefix)
    insert (v -> prefix, v -> vendor, & vt),
      v ++;
}


/* Lookup for a vendor in the hash table */
char * vendor (char * mac)
{
  char key [9] = { '\0' };
  char * vendor;

  strncpy (key, mac, 8);          /* only the first 8 chars are meaningful */

  return (vendor = lookup (key, & vt)) ? vendor : NULL;
}


#if defined(FIXME)
char ** vtkeys (void)
{
  return htkeys (& vt);
}
#endif /* FIXME */
