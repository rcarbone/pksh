/*
 * pksh - The Packet Shell
 *
 * R. Carbone (rocco@tecsiel.it)
 * 2003, 2008-2009, 2022
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
static char __id__ []       = "A hack of the popular 'tcsh' with builtin extensions for network monitoring.\n";


/* Global variable here */
pksh_run_t pksh_run;


/* Set extensions completions */
static void set_completions (void)
{
  int i;

  int cargc = 0;
  char ** cargv = NULL;

  int hargc = 0;
  char ** hargv = NULL;

  cargv = argsmore (cargv, "bytes");
  cargv = argsmore (cargv, "packets");
  cargv = argsmore (cargv, "pkarp");
  cargv = argsmore (cargv, "pkcal");
  cargv = argsmore (cargv, "pkfinger");
  cargv = argsmore (cargv, "pkhosts");
  cargv = argsmore (cargv, "pklast");
  cargv = argsmore (cargv, "pkwho");
  cargv = argsmore (cargv, "protocols");
  cargv = argsmore (cargv, "services");
  cargv = argsmore (cargv, "throughput");

  cargc = argslen (cargv);

  for (i = 0; i < cargc; i ++)
    {
      hargv = argsmore (NULL, "complete");
      hargv = argsmore (hargv, cargv [i]);
      hargv = argsmore (hargv, "p/\\*/$hosts/");

      hargc = argslen (hargv);

      /* add the completion directive to the list of completions */
      tcsh_builtins (hargc, hargv);

      argsclear (hargv);
    }

  argsclear (cargv);
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


/* Just few initialization steps */
void pksh_init (char * progname, int quiet)
{
  pksh_run . progname  = progname;
  gettimeofday (& pksh_run . boottime, NULL);   /* Set time the shell boots */
  pksh_run . prompt      = NULL;                /* user prompt               */
  pksh_run . pcolor      = NULL;                /* default prompt ansi-color */
  pksh_run . bell        = false;
  pksh_run . initialized = false;

  if (! quiet)
    {
      /* Hello world! this is the shell speaking */
      helloworld (progname);

      if (! (getuid () && geteuid ()))
	xprintf ("WARNING: YOU ARE SUPERUSER !!!\n");
      xprintf ("\nType 'pkhelp' for the list of builtin extensions implemented by this shell\n\n");
    }

  /* Set unbuffered stdout */
  setvbuf (stdout, NULL, _IONBF, 0);

  /* Set the $pksh variable */
  tcsh_set_variable (PKSH_PACKAGE, PKSH_VERSION);

  /* Set the complete commands */
  set_completions ();

  /* Initialize the vendor hash table */
  vtfill ();

  /* Initialize the OS fingerprint hash table */
  osfingerprintfill ();

  /* Set the $prompt variable */
  pksh_prompt (NULL);
}
