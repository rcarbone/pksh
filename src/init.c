/*
 * init.c - All that serves to initialze 'pksh', the Packet Shell, that is
 *          a hack of the 'tcsh' for packets, bytes, hosts and protocols counts
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
#include <unistd.h>
#include <sys/time.h>

/* Private header file(s) */
#include "pksh.h"


/* Global variable here.  Sorry! */
struct timeval boottime;


/* Identifiers */
static char __version__ []   = PKSH_VERSION;
static char __released__ []  = PKSH_RELEASED;
static char __authors__ []   = PKSH_AUTHOR;
static char __copyright__ [] = PKSH_COPYRIGHT;
static char __reserved__ []  = "All rights reserved";
static char __id__ []        = "A hack of the popular 'tcsh' with built-ins extensions for network monitoring.\n";
static char __what__ []      = "It allows you to take a look at the traffic on your network without leaving your shell!";
static char __free__ []      =
"  This program is open-source software; you can redistribute it and/or modify\n\
  it under the terms of the GNU General Public License as published by\n\
  the Free Software Foundation; either version 3 of the License, or\n\
  (at your option) any later version.";
static char __notice__ []    =
"  This program is distributed in the hope that it will be useful,\n\
  but WITHOUT ANY WARRANTY; without even the implied warranty of\n\
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n\
  included GNU General Public License in file COPYING for more details.";


#if defined(FIXME)
/* Well formatted banner should look like... */
char * pksh_banner (char * interface)
{
  static char room [BUFSIZ] = { '\0' };

  sprintf (room, "%s %s (%s) listening on [%s]", progname, __version__, __DATE__, interface ? interface : "none");

  return room;
}
#endif /* FIXME */


/* Set extensions completions */
static void set_completions (void)
{
  int i;

  int cargc = 0;
  char ** cargv = NULL;

  int hargc = 0;
  char ** hargv = NULL;

  cargv = argsadd (cargv, "bytes");
  cargv = argsadd (cargv, "packets");
  cargv = argsadd (cargv, "pkarp");
  cargv = argsadd (cargv, "pkcal");
  cargv = argsadd (cargv, "pkfinger");
  cargv = argsadd (cargv, "pkhosts");
  cargv = argsadd (cargv, "pklast");
  cargv = argsadd (cargv, "pkwho");
  cargv = argsadd (cargv, "protocols");
  cargv = argsadd (cargv, "services");
  cargv = argsadd (cargv, "throughput");

  cargc = argslen (cargv);

  for (i = 0; i < cargc; i ++)
    {
      hargv = argsadd (NULL, "complete");
      hargv = argsadd (hargv, cargv [i]);
      hargv = argsadd (hargv, "p/\\*/$hosts/");

      hargc = argslen (hargv);

      /* add the completion directive to the list of completions */
      tcsh_builtins (hargc, hargv);

      argsfree (hargv);
    }

  argsfree (cargv);
}


/* You are welcome! */
static void helloworld (char * program)
{
  static int once = 0;

  if (! once)
    {
      xprintf ("\n");
      xprintf ("-- %s %s (%s) --\n", program, __version__, __released__);
      xprintf ("%s\n", __id__);
      xprintf ("%s\n", __what__);
      xprintf ("\n");
      xprintf ("%s %s. %s\n", __copyright__, __authors__, __reserved__);
      xprintf ("\n");
      xprintf ("%s\n", __free__);
      xprintf ("\n");
      xprintf ("%s\n", __notice__);
      xprintf ("\n");

      once = 1;
    }
}


/* Just few initialization steps */
void pkshinit (char * progname)
{
  /* Set time the shell boots */
  gettimeofday (& boottime, NULL);

  /* Hello world! this is pksh speaking */
  helloworld (progname);

  /* Set the complete commands */
  set_completions ();

  if (! (getuid () && geteuid ()))
    xprintf ("WARNING: YOU ARE SUPERUSER !!!\n");
  xprintf ("\nType 'pkhelp' for the list of built-ins extensions implemented by this shell\n\n");

  /* Initialize the vendor hash table */
  vtfill ();

  /* Initialize the OS fingerprint hash table */
  osfingerprintfill ();

  /* Set the prompt */
  pkshprompt (NULL);
}
