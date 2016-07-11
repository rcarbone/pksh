/*
 * wrapper.c - Wrapper around original pksh_xxx()
 *             for use with tcsh
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


/* tcsh header file(s) */
#include "sh.h"

#if !defined(FIXME)
void docomplete (Char **, struct command *);
#endif /* FIXME */


/* Private header file(s) */
#include "pksh.h"

typedef int handler (int argc, char * argv []);


/* My own variables as extensions to those available from tcsh */
static Char hosts [] = {'h', 'o', 's', 't', 's', '\0'};   /* just a new variable */
static Char * extensions [];                              /* array of new built-ins */
static int extension (Char ** e);                         /* Forward declaration */


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
  nargv = argsadd (NULL, "set");
  nargv = argsadd (nargv, "hosts");
  nargv = argsadd (nargv, "=");
  nargv = argsadd (nargv, "(");

  for (s = sorted; s && * s; s ++)
    nargv = argsadd (nargv, * s);

  nargv = argsadd (nargv, ")");

  tcsh_builtins (argslen (nargv), nargv);

  argsfree (nargv);
  argsfree (sorted);
  argsfree (keys);
}


/* How to call the pksh_xxx functions from tcsh */
static void tcsh_xxx (Char ** v, handler * func)
{
  Char ** vv = v;                      /* an interator in the 'v' array */
  struct varent * nn = adrof (hosts);  /* this is the address of the $hosts variable */

  /* insert command name */
  char ** argv = argsadd (NULL, short2str (* vv ++));

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
		argv = argsadd (argv, * w ++);

	      /* free memory returned by globargs() */
	      argsfree (gargv);
	    }
	  else
	    /* add the term to the list of arguments */
	    argv = argsadd (argv, what);

	  free (what);
	  vv ++;
	}
    }
  else
    while (* vv)
      argv = argsadd (argv, short2str (* vv ++));

  /* It's time to execute the function */
  if ((* func) (argslen (argv), argv))
    setcopy (STRstatus, Strsave (STR1), VAR_READWRITE);  /* set the $status variable */
}


/* How to call the tcsh built-ins from pksh_xxx functions
 * [argv *** MUST *** be NULL terminated]
 */
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


/* Definitions for all the extensions to the Packet Shell will be automatically inserted here by the configure script */


