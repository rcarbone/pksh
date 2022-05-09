/*
 * pksh - The Packet Shell
 *
 * R. Carbone (rocco@tecsiel.it)
 * 2003, 2008-2009, 2022
 *
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Load and access the 'ettercap' passive OS fingerprint database
 * into memory to resolve OS fingerprints names at run-time
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
#include "ettercap.h"


#define DEFAULT_FINGER_SIZE 256         /* initial hash table size for passive OS fingerprints names */

/* The 'ettercap' signatures are prefixed by 28 digits coded as WWWW:MSS:TTL:WS:S:N:D:T:F:LL */
#define FPLEN    30


/* The passive OS fingerprints hash table */
static struct hash_table osfpht;


/* Insert an element (key, value) into the hash table */
static void insert (char * k, char * v, struct hash_table * t)
{
  struct datum pair;

  /* The key is the tcp fingerprint and the value is the OS name */
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

  found = hash_table_search (t, & pair);

  return (found = hash_table_search (t, & pair)) ? found -> val : NULL;
}


/* Initialize the OS fingerprint hash table */
void osfingerprintfill (void)
{
  ettercap_t * os = fingerprints;

  /* Initialize the hash table */
  osfpht . size = DEFAULT_FINGER_SIZE;
  hash_table_init (& osfpht);

  while (os && os -> prefix)
    insert (os -> prefix, os -> system, & osfpht),
      os ++;
}


/* Lookup for a match in the passive OS fingerprints hash table */
char * osfingerprintmatch (char * fp)
{
  char * os;
  char wildcard [FPLEN];

  if ((os = lookup (fp, & osfpht)))
    return os;                     /* exact match */

  /* if not found search with wildcard MSS but the same window size */
  if (strncmp (fp + 5, "_MSS", 4))
    {
      strcpy (wildcard, fp);
      memcpy (wildcard + 5, "_MSS", 4);
      if ((os = lookup (fp, & osfpht)))
	return os;
    }

  return lookup (fp, & osfpht);
}
