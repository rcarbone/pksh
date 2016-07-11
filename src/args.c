/*
 * args.c - How to handle dynamic arrays of strings
 *
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
 *                    _        _
 *              _ __ | | _____| |__
 *             | '_ \| |/ / __| '_ \
 *             | |_) |   <\__ \ | | |
 *             | .__/|_|\_\___/_| |_|
 *             |_|
 *
 *            'pksh', the Packet Shell
 *
 *            (C) Copyright 2003-2009
 *   Rocco Carbone <rocco /at/ ntop /dot/ org>
 *
 * Released under the terms of GNU General Public License
 * at version 3;  see included COPYING file for details
 *
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
 *
 */


/* Operating System header file(s) */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


/* Macros for min/max */
#if !defined MAX
# define MAX(a,b) (a > b ? a : b)
#endif


/* How many items are in a the NULL terminated table? */
static int vargslen (void * argv [])
{
  int argc = 0; while (argv && * argv ++) argc ++; return argc;
}


/* Add an element to the table of arguments */
void ** vargsadd (void * argv [], void * p)
{
  int argc = vargslen (argv);
  if (p)
    {
      /* buy memory */
      if (! (argv = realloc (argv, (1 + argc + 1) * sizeof (p))))
	return (NULL);
      argv [argc ++] = p;
      argv [argc]    = NULL;        /* do the table NULL terminated */
    }

  return argv;
}


/* Check and free a pointer */
void * safefree (void * a)
{
  if (a) free (a);
  return NULL;
}


/* Check, free and duplicate a pointer */
void * safedup (void * a, void * b)
{
  safefree (b);
  return a ? strdup (a) : a;
}


/* Compute the len of the array */
int argslen (char * argv [])
{
  int argc = 0; while (argv && * argv ++) argc ++; return argc;
}


/* Add an element to the array of arguments */
char ** argsadd (char * argv [], char * s)
{
  if (s)
    {
      int argc = argslen (argv);

      /* buy memory for an item */
      if (! (argv = realloc (argv, (1 + argc + 1) * sizeof (char *))))
	return NULL;
      argv [argc ++] = strdup (s);
      argv [argc]    = NULL;        /* do the array NULL terminated */
    }

  return argv;
}


/* Lookup for an element into the array of arguments */
int member (char * argv [], char * item)
{
  int i = -1;

  while (item && argv && * argv)
    if (! strcmp (* argv ++, item))
      return i + 1;
    else
      i ++;

  return -1;
}


/* Remove an item from the table of arguments */
char ** argsrm (char * argv [], char * item)
{
  int i;
  int j;
  int argc;

  if ((i = member (argv, item)) != -1)
    {
      argc = argslen (argv);
      free (argv [i]);                   /* free the argument */

      for (j = i; j < argc - 1; j ++)    /* move pointers back one position */
	argv [j] = argv [j + 1];

      argv [j] = NULL;                   /* terminate the array */

      if (argc > 1)
	argv = realloc (argv, argc * sizeof (char *));  /* the size is argc not argc-1 because of trailing NULL */
      else
	free (argv);
    }

  return argc > 1 ? argv : NULL;
}


/* Replace the element 's' in the array of arguments with 'd' */
void argsreplace (char * argv [], char * s, char * d)
{
  int i;

  if ((i = member (argv, s)) != -1)
    {
      safefree (argv [i]);                   /* free the argument */
      argv [i] = strdup (d);
    }
}


/* Free memory associated to a NULL terminated array of arguments */
void argsfree (char * argv [])
{
  char ** p = argv;

  if (! argv)
    return;

  while (* p)
    free (* p ++);
  free (argv);
}


/* Duplicate the NULL terminated array 'argv' */
char ** argsdup (char * argv [])
{
  char ** dup = NULL;
  if (argv)
    while (* argv)
      dup = argsadd (dup, * argv ++);

  return dup;
}


/* Concatenate the NULL terminated array 'b' to 'a' */
char ** argscat (char * a [], char * b [])
{
  while (b && * b)
    a = argsadd (a, * b ++);

  return a;
}


/* Print the arguments in a single line (arguments separated by character in c) */
void argsline (char * argv [], char c)
{
  while (argv && * argv)
    {
      printf ("%s", * argv ++);
      if (* argv && (strlen (* argv) != 1 || ** argv != c))
        printf ("%c", c);
    }
  printf ("\n");
}


/* Print the arguments in 'argc' rows (one argument for line) */
void argsrows (char * argv [])
{
  int argc = 0;
  while (argv && * argv)
    printf ("%3d. \"%s\"\n", ++ argc, * argv ++);
}


/* Check for an item in a blank separated list of names */
int argsmemberof (char * name, char * list)
{
  char * item;

  /* First item */
  item = strtok (list, " ");
  while (item)
    {
      if (! strcmp (item, name))
        return 1;
      /* Next item */
      item = strtok (NULL, " ");
    }

  return 0;
}


/* Split a string into pieces */
char ** argssplit (char * str, char * separator)
{
  char ** argv = NULL;
  char * param;
  char * rest = NULL;
  char * data;
  char * m;

  if (! str || ! separator)
    return NULL;

  data = strdup (str);                       /* this is due strtok_r() modifies the input buffer 'str' */
  m = data;

  param = strtok_r (data, separator, & rest);
  while (param)
    {
      /* Add current field to the array */
      argv = argsadd (argv, param);

      /* Process empty fields (add the separator) */
      if (rest && * rest == * separator)
	{
	  char * p = rest;
	  while (* p ++ == * separator)
	    argv = argsadd (argv, separator);
	}
      /* Next field */
      param = strtok_r (NULL, separator, & rest);
    }

  safefree (m);
  return argv;
}


/* Split a string into pieces */
char ** argspieces (char * list, char * separator)
{
  char ** argv = NULL;
  char * param;
  char * names = list ? strdup (list) : NULL;

  while (names && (param = strtok (! argv ? names : NULL, separator)))
    argv = argsadd (argv, param);

  safefree (names);

  return argv;
}


/* Split a blank separated list of strings into pieces */
char ** argsblanks (char * list)
{
  return argspieces (list, " ");
}


/* Find the longest name */
int argslongest (char * argv [])
{
  int longest = 0;

  while (argv && * argv)
    {
      longest = MAX (longest, strlen (* argv));
      argv ++;
    }
  return longest;
}


static int sort_by_name (const void * _a, const void * _b)
{
  return strcmp (* (char **) _a, * (char **) _b);
}


/* Sort an array and return the sorted one */
char ** argssort (char * argv [])
{
  int argc = argslen (argv);
  char ** sorted;

  if (! argv)
    return NULL;

  sorted = argsdup (argv);
  qsort (sorted, argc, sizeof (char *), sort_by_name);

  return sorted;
}


/* Join the items in 'argv' */
char * argsjoin (char * argv [])
{
  int size = 0;
  char * join = NULL;
  while (argv && * argv)
    {
      size += (strlen (* argv) + 1 + 1);  /* '\n' plus a blank separator */
      if (join)
	{
	  strcat (join, " ");
	  join = realloc (join, size);
	  strcat (join, * argv ++);
	}
      else
	{
	  join = calloc (size, 1);
	  strcpy (join, * argv ++);
	}
    }
  return join;
}
