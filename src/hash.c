/*
** HASH: Simple hash table implementation.
** Copyright (C) 2000 Michael W. Shaffer <mwshaffer@yahoo.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.  
**
** You should have received a copy of the GNU General Public License
** along with this program (see the file COPYING). If not, write to:
**
** The Free Software Foundation, Inc.
** 59 Temple Place, Suite 330,
** Boston, MA  02111-1307  USA
*/

#include <stdlib.h>
#include <math.h>

#include "hash.h"

/* PRIMES: Simple prime number functions */
inline
unsigned int find_prime (unsigned long max)
{
  unsigned int i = 0;
  unsigned int f = 0;
  unsigned int prime = 1;

  for (i = max ; i > 1 ; i--) {
    if ((i % 2) == 0)
      goto NOTPRIME;
    for (f = 2 ; f <= ((unsigned int) floor (sqrt ((double) i))) ; f++) {
      if ((i % f) == 0)
	goto NOTPRIME;
    }
    prime = i;
    goto EXIT;
  NOTPRIME:
    continue;
  }

 EXIT:
  return prime;
}


unsigned long hash_pjw (char *value)
{
	unsigned long h = 0;
	unsigned long g = 0;

	while (*value) {
		h = (h << 4) + *(value++);
		if ((g = h & 0xF0000000))
			h ^= g >> 24;
		h &= ~g;
	}
	return h;
}

void hash_table_init (struct hash_table *h)
{
	int i = 0;

	if (!h)
		return;

	if (h->size < 1)
		h->size = 100;
	if (!h->func)
		h->func = hash_pjw;

	h->size = (unsigned int) find_prime (h->size);
	h->tbl = (struct list *) malloc (h->size * (sizeof (struct list)));
	if (!h->tbl)
		return;
	memset (h->tbl, 0, (h->size * sizeof (struct list)));

	for (i = 0 ; i < h->size ; i++) {
		list_init (&(h->tbl[i]));
	}

	return;
}

void hash_table_free (struct hash_table *h)
{
	int i = 0;
	struct datum *d = NULL;
	struct list_item *curr = NULL;

	if (!h)
		return;

	for (i = 0 ; i < h->size ; i++) {
		for (curr = h->tbl[i].head ; curr ; curr = curr->next) {
			if (curr->data) {
				d = (struct datum *) curr->data;
				if (d->key)
					free (d->key);
				if (d->val)
					free (d->val);
			}
		}
		list_free (&(h->tbl[i]));
	}

	if (h->tbl)
		free (h->tbl);

	h->func = NULL;
	h->size = 0;
	h->tbl = NULL;

	return;
}

struct datum *hash_table_insert (struct hash_table *h, struct datum *d)
{
	int slot = 0;  
	struct datum *new = NULL;
	struct list_item *item = NULL;

	if (!(d && h && (h->size > 0) && h->func && h->tbl))
		return NULL;

	new = (struct datum *) malloc (sizeof (struct datum));
	if (!new)
		goto ERROR;
	memset (new, 0, (sizeof (struct datum)));

	new->ksize = d->ksize;
	new->key = (void *) malloc (new->ksize + 1);
	if (!new->key)
		goto ERROR;
	memset (new->key, 0, (new->ksize + 1));
	memcpy (new->key, d->key, new->ksize);

	new->vsize = d->vsize;
	new->val = (void *) malloc (new->vsize + 1);
	if (!new->val)
		goto ERROR;
	memset (new->val, 0, (new->vsize + 1));
	memcpy (new->val, d->val, new->vsize);

	slot = (int) (h->func (d->key) % h->size);
	item = list_insert (&(h->tbl[slot]), (void *) new, sizeof (struct datum));
	goto EXIT;

ERROR:
	if (new && (new->key))
		free (new->key);
	if (new && (new->val))
		free (new->val);
EXIT:
	if (new)
		free (new);
	return (struct datum *) item->data;
}

struct datum *hash_table_search (struct hash_table *h, struct datum *k)
{
	int slot = 0;
	struct list_item *curr = NULL;
	struct datum *d = NULL;

	if (!(k && h && (h->size > 0) && h->func && h->tbl))
		goto EXIT;

	slot = (int) (h->func (k->key) % h->size);
	for (curr = h->tbl[slot].head ; curr ; curr = curr->next) {
		d = (struct datum *) curr->data;
		if (d->ksize == k->ksize){
			if (!memcmp (d->key, k->key, d->ksize))
				goto EXIT;
		}
	}
	d = NULL;

EXIT:
	return d;
}

static struct list_item *hash_table_search2 (struct hash_table *h, struct datum *k)
{
	int slot = 0;
	struct list_item *curr = NULL;
	struct datum *d = NULL;

	if (!(k && h && (h->size > 0) && h->func && h->tbl))
		goto EXIT;

	slot = (int) (h->func (k->key) % h->size);
	for (curr = h->tbl[slot].head ; curr ; curr = curr->next) {
		d = (struct datum *) curr->data;
		if (d->ksize == k->ksize){
			if (!memcmp (d->key, k->key, d->ksize))
				goto EXIT;
		}
	}
	curr = NULL;

EXIT:
	return curr;
}

void hash_table_delete (struct hash_table *h, struct datum *k)
{
	struct datum *d = NULL;
	struct list_item *l = NULL;

	if (!(k && h && (h->size > 0) && h->func && h->tbl))
		return;

	if ((l = hash_table_search2 (h, k))) {
		d = (struct datum *) l->data;
		if (d->key)
			free (d->key);
		if (d->val)
			free (d->val);
		list_delete ((struct list_item *) l);
	}

	return;
}


/* Rocco Carbone 2Q 2008 */
int vargslen (void * argv []);
void ** vargsadd (void * argv [], void * p);
char ** argsadd (char * argv [], char * s);

struct datum *hash_table_refer (struct hash_table *h, struct datum *d)
{
	int slot = 0;  
	struct datum *new = NULL;
	struct list_item *item = NULL;

	if (!(d && h && (h->size > 0) && h->func && h->tbl))
		return NULL;

	new = (struct datum *) malloc (sizeof (struct datum));
	if (!new)
		goto ERROR;
	memset (new, 0, (sizeof (struct datum)));

	new->ksize = d->ksize;
	new->key = (void *) malloc (new->ksize + 1);
	if (!new->key)
		goto ERROR;
	memset (new->key, 0, (new->ksize + 1));
	memcpy (new->key, d->key, new->ksize);

	new->vsize = d->vsize;
	new->val = d -> val;    /* reference only the object but do not local copy */

	slot = (int) (h->func (d->key) % h->size);
	item = list_insert (&(h->tbl[slot]), (void *) new, sizeof (struct datum));
	goto EXIT;

ERROR:
	if (new && (new->key))
		free (new->key);
EXIT:
	if (new)
		free (new);
	return (struct datum *) item->data;
}


/* Return the # of items in the hash table 't' */
int htno (struct hash_table * t)
{
  int argc = 0;
  int i = 0;
  struct list_item * item;

  for (i = 0; i < t -> size; i ++)
    for (item = t -> tbl [i] . head; item; item = item -> next)
      argc ++;

  return argc;
}


/* Return all the keys in the hash table 't' */
char ** htkeys (struct hash_table * t)
{
  int i = 0;
  struct list_item * item;
  char ** keys = NULL;

  for (i = 0; i < t -> size; i ++)
    for (item = t -> tbl [i] . head; item; item = item -> next)
      keys = argsadd (keys, ((struct datum *) item -> data) -> key);

  return keys;
}


/* Return all the values in the hash table 't' */
void ** htvalues (struct hash_table * t)
{
  int i = 0;
  struct list_item * item;
  void ** values = NULL;

  for (i = 0; i < t -> size; i ++)
    for (item = t -> tbl [i] . head; item; item = item -> next)
      values = vargsadd (values, ((struct datum *) item -> data) -> val);

  return values;
}
