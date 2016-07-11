/*
** LIST: Simple doubly-linked list implementation.
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

#ifndef __LIST_H__
#define __LIST_H__

#include <string.h>

struct list_item {
	long size;
	void *data;
	struct list_item *prev;
	struct list_item *next;
	struct list *list;
};

struct list {
	struct list_item *head;
};

void list_init (struct list *list);
void list_free (struct list *list);
struct list_item *list_insert (struct list *list, void *data, long size);
struct list_item *list_search (struct list *list, void *data, long size);
void list_delete (struct list_item *item);

#endif /* __LIST_H__ */

