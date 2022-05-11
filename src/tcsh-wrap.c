/*
 * pksh - The Packet Shell
 *
 * R. Carbone (rocco@tecsiel.it)
 * 2003, 2008-2009, 2022
 *
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Wrapper around original pksh_xxx() functions for use with tcsh
 */


/* Avoid warning: 'tcsh_xxx' defined but not used [-Wunused-function] */
#if defined(__GNUC__)
#pragma GCC diagnostic ignored   "-Wunused-function"
#else /* defined(__clang__) */
#pragma clang diagnostic ignored "-Wunused-function"
#endif


/* tcsh header */
#include "sh.h"

extern int TermH;      /* number of real screen lines */
extern int TermV;      /* screen width                */

/* defined in file tw.decls.h */
void docomplete (Char **, struct command *);

/* Project header */
#include "pksh.h"


/* Typedefs */
typedef int handler (int argc, char * argv []);

/* =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */

/* My own variables as extensions to those available from tcsh */
static Char hosts [] = {'h', 'o', 's', 't', 's', '\0'};   /* just a new variable */


/* Fill the $hosts variable */
static void fillhosts (void)
{
  char * name = getintfname ();
  interface_t * interface = name ? intfbyname (interfaces, name) : NULL;

  /* The unsorted array of unique hosts identifiers */
  char ** keys;
  char ** s;

  char ** nargv;

  /* Lookup for the name of the active interface in the table of the enabled interfaces */
  if (! interface || interface -> status != INTERFACE_ENABLED || ! interface -> pkts_total)
    return;

  /* Set the $hosts variable */
  nargv = argsmore (NULL, "set");
  nargv = argsmore (nargv, "hosts");
  nargv = argsmore (nargv, "=");
  nargv = argsmore (nargv, "(");

  /* Get all the currently known unique MAC identifiers */
  if (htno (& interface -> hwnames))
    {
      keys = htkeys (& interface -> hwnames);
      for (s = keys; s && * s; s ++)
	nargv = argsmore (nargv, * s);
      argsclear (keys);
    }

  /* Get all the currently known unique IP */
  if (htno (& interface -> ipnames))
    {
      keys = htkeys (& interface -> ipnames);
      for (s = keys; s && * s; s ++)
	nargv = argsmore (nargv, * s);
      argsclear (keys);
    }

  /* Get all the currently known unique hostnames */
  if (htno (& interface -> hostnames))
    {
      keys = htkeys (& interface -> hostnames);
      for (s = keys; s && * s; s ++)
	nargv = argsmore (nargv, * s);
      argsclear (keys);
    }

  nargv = argsmore (nargv, ")");

  /* Update the $hosts variable */
  tcsh_builtins (argslen (nargv), nargv);

  argsclear (nargv);
}


/* =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */


/* Handle completion */
static void handle_completion (char * argv [])
{
  Char ** v = blk2short (argv);

  if (! strcmp (argv [0], "set"))
    doset (v, NULL);
  else if (! strcmp (argv [0], "unset"))
    unset (v, NULL);
  else if (! strcmp (argv [0], "complete"))
    docomplete (v, NULL);
  else if (! strcmp (argv [0], "echo"))
    doecho (v, NULL);
}


/* Set the [$name] array */
static void set_array (char * name, char ** values)
{
  char ** argv;
  char ** n;
  char ** sorted;

  if (! values)
    return;

  /* Sort currently known unique table names */
  sorted = argssort (values);

  /* Set the $var variable */
  argv = argsmore (NULL, "set");
  argv = argsmore (argv, name);
  argv = argsmore (argv, "=");

  argv = argsmore (argv, "(");
  for (n = sorted; n && * n; n ++)
    argv = argsmore (argv, * n);
  argv = argsmore (argv, ")");

  handle_completion (argv);

  argsclear (sorted);
  argsclear (argv);
}


/* How to call the [pksh] extensions from tcsh */
static void tcsh_xxx (Char ** v, handler * func)
{
  Char ** vv = v;                                               /* interator in the 'v' array */

  /* Insert command name as argv [0] */
  char ** argv = argsmore (NULL, short2str (* vv ++));

  /* Check if the extension in 'v' should also update the $hosts variable */
  if (! strcmp (argv [0], "pkarp") || ! strcmp (argv [0], "pkhosts") ||
      ! strcmp (argv [0], "xxx") || ! strcmp (argv [0], "xxx") || ! strcmp (argv [0], "xxx"))
    {
      struct varent * nn = adrof (hosts);                           /* address of the $hosts variable */

      /* Update the [$hosts] variable for hosts names TAB-completion and globbing (only a subset of commands) */
      fillhosts ();

      /* optional parameters on the command line? */
      while (nn && * vv)
	{
	  char * what = strdup (short2str (* vv));          /* Why do I need a local copy? */
	  char ** gargv;

	  gargv = globargs (blklen (nn -> vec), short2blk (nn -> vec), what);
	  if (gargv)
	    {
	      /* Found! We have a subset to look for */
	      char ** w = gargv;

	      /* insert each term in the list of arguments */
	      while (* w)
		argv = argsmore (argv, * w ++);

	      /* free memory returned by globargs() */
	      argsclear (gargv);
	    }
	  else
	    /* add the term to the list of arguments */
	    argv = argsmore (argv, what);

	  free (what);
	  vv ++;
	}
    }
  else
    while (* vv)
      argv = argsmore (argv, short2str (* vv ++));

  /* It's time to execute the function */
  if ((* func) (argslen (argv), argv))
    setcopy (STRstatus, Strsave (STR1), VAR_READWRITE);         /* set the $status variable */
}


/* Rows of the terminal */
unsigned tcsh_screen_rows (void)
{
  return TermH;
}


/* Cols of the terminal */
unsigned tcsh_screen_cols (void)
{
  return TermV;
}


/* Fill the [$name] variable to [value] */
void tcsh_set_variable (char * name, char * value)
{
  char ** argv;

  argv = argsmore (NULL, "set");
  argv = argsmore (argv, name);
  argv = argsmore (argv, "=");
  argv = argsmore (argv, value);

  doset (blk2short (argv), NULL);

  argsclear (argv);
}


/* Unset the [$var] variable */
void tcsh_unset_variable (char * var)
{
  char ** argv = argsmore (NULL, "unset");
  argv = argsmore (argv, var);

  handle_completion (argv);

  argsclear (argv);
}


/* How to call the [pksh] extensions from tcsh */
void tcsh_builtins (int argc, char * argv [])
{
  Char ** v;

  if (argc && argv)
    {
      v = blk2short (argv);

      if (! strcmp (argv [0], "set"))
	doset (v, NULL);
      else if (! strcmp (argv [0], "complete"))
	docomplete (v, NULL);
      else if (! strcmp (argv [0], "echo"))
	doecho (v, NULL);
    }
}


/* Definitions for builtin extensions to the shell will be automatically inserted here by the configure script */
