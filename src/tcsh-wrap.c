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


extern void unset (Char **, struct command *);
extern void docomplete (Char **, struct command *);

/* Project header */
#include "pksh.h"


/* Typedefs */
typedef int handler (int argc, char * argv []);

/* =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- */

/* My own variables as extensions to those available from tcsh */
static Char hosts [] = {'h', 'o', 's', 't', 's', '\0'};   /* just a new variable */
static Char * extensions [];                              /* array of new builtins */


/* Check if the extension in 'e' should also update the $hosts variable */
static int extension (Char ** e)
{
  Char ** ext = extensions;
  while (* ext)
    if (eq (* e, * ext ++))
      return 1;
  return 0;
}


/* Fill the $hosts variable */
static void fillhosts (void)
{
  char * name;
  interface_t * interface;

  /* The unsorted array of unique hosts identifiers */
  char ** keys;

  /* The sorted one */
  char ** sorted;
  char ** s;

  char ** nargv;

  /* Lookup for the name of the active interface in the table of the enabled interfaces */
  if ((! (interface = intfbyname (interfaces, name = getintfname ()))) || interface -> status != INTERFACE_ENABLED)
    return;

  /* Get and sort all the currently known unique host identifiers */
  sorted = argssort (keys = hostskeys (interface));

  /* Set the $hosts variable */
  nargv = argsmore (NULL, "set");
  nargv = argsmore (nargv, "hosts");
  nargv = argsmore (nargv, "=");
  nargv = argsmore (nargv, "(");

  for (s = sorted; s && * s; s ++)
    nargv = argsmore (nargv, * s);

  nargv = argsmore (nargv, ")");

  tcsh_builtins (argslen (nargv), nargv);

  argsclear (nargv);
  argsclear (sorted);
  argsclear (keys);
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


/* How to call the [pksh] extensions from tcsh */
static void tcsh_xxx (Char ** v, handler * func)
{
  Char ** vv = v;                                               /* interator in the 'v' array */
  struct varent * nn = adrof (hosts);                           /* address of the $hosts variable */

  /* Insert command name as argv [0] */
  char ** argv = argsmore (NULL, short2str (* vv ++));

  /* Check if the extension in 'v' should also update the $hosts variable */
  if (extension (v))
    {
      /* Fill the $hosts variable */
      fillhosts ();

      /* optional parameters on the command line? */
      while (nn && * vv)
	{
	  char ** gargv = NULL;
	  char * what = strdup (short2str (* vv));          /* Why do I need a local copy? */

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
    setcopy (STRstatus, Strsave (STR1), VAR_READWRITE);  /* set the $status variable */
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

  v = blk2short (argv);

  if (! strcmp (argv [0], "set"))
    doset (v, NULL);
  else if (! strcmp (argv [0], "complete"))
    docomplete (v, NULL);
  else if (! strcmp (argv [0], "echo"))
    doecho (v, NULL);
}


/*
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
 * Do not edit anything below, configure creates it.
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
 */

/* Definitions for builtin extensions to the shell will be automatically inserted here by the configure script */
