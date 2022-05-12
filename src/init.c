 /*
 * pksh - The Packet Shell
 *
 * R. Carbone (rocco@tecsiel.it)
 * 2008-2009, 2022
 *
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * All that serves to initialize the Packet Shell [pksh],
 * a hack of the [tcsh] for packets, bytes, hosts and protocols counts.
 */


/* System headers */
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <time.h>
#include <sys/time.h>
#include <signal.h>

/* tcsh header */
#include "sh.h"

/* Project header */
#include "pksh.h"


/* Identifiers */
static char __version__ []  = PKSH_VERSION;
static char __authors__ []  = PKSH_AUTHOR;
static char __released__ [] = PKSH_RELEASED;
static char __id__ []       = "A hack of the popular 'tcsh' with builtin extensions for network monitoring.";


/* This is the list of commands where completion on variable [$hosts] would take effect */
static char * completions [] =
  { "packets", "bytes", "protocols", "throughput", "services", "pkhosts", "pkarp", "pklast", "pkwho", "pkfinger", NULL };


/* Global variable here */
pksh_run_t pksh_run;



/* Initialize the runtime variable */
static void init_runtime (char * progname)
{
  pksh_run . progname  = progname;
  gettimeofday (& pksh_run . boottime, NULL);   /* Set time the shell boots */
  pksh_run . prompt      = NULL;                /* user prompt               */
  pksh_run . pcolor      = NULL;                /* default prompt ansi-color */
  pksh_run . bell        = false;
  pksh_run . initialized = false;
}


/* Set the complete list of completions */
static void set_completions (int cargc, char * cargv [])
{
  int i;

  char ** hargv = NULL;

  for (i = 0; i < cargc; i ++)
    {
      int hargc;

      /* complete pkhosts 'p/\*\/$hosts' */
      hargv = argsmore (NULL, "complete");
      hargv = argsmore (hargv, cargv [i]);
      hargv = argsmore (hargv, "p/\\*/$hosts/");

      hargc = argslen (hargv);

      /* Add the completion directive to the list of completions */
      tcsh_builtins (hargc, hargv);

      argsclear (hargv);
    }
}


/* You are welcome! */
static void helloworld (char * progname)
{
  static bool once = false;

  if (! once)
    {
      xprintf ("\n");
      xprintf ("-- %s %s (%s) -- %s\n", progname, __version__, __released__, __authors__);
      xprintf ("%s\n", __id__);

      once = true;
    }
}


/* Evaluate if 'cmd' is hosts-completion command */
bool check_completion (char * cmd)
{
  return argsmember (completions, cmd) != -1 ? true : false; 
}


/* Called once when the shell boots just to perform few initialization steps */
void pksh_init (char * progname, int quiet)
{
  /* Initialize runtime variable to default values */
  init_runtime (progname);

  if (! quiet)
    {
      /* Hello world! this is the shell speaking */
      helloworld (progname);

      if (! (getuid () && geteuid ()))
	xprintf ("WARNING: YOU ARE SUPERUSER !!!\n");
      xprintf ("Type 'help' for the list of builtin extensions implemented by this shell.\n\n");
    }

  /* Set unbuffered stdout */
  setvbuf (stdout, NULL, _IONBF, 0);

  /* Initialize the vendor hash table */
  vtfill ();

  /* Initialize the OS fingerprint hash table */
  osfingerprintfill ();

  /* Define the set of [pksh] commands where the completion would take effect on the [$hosts] variable */
  set_completions (argslen (completions), completions);

  /* Set the $pksh variable */
  tcsh_set_variable (PKSH_PACKAGE, PKSH_VERSION);

  /* Set the $prompt variable */
  pksh_prompt (NULL);
}
