/*
 * prompt.c - How to manage the Packet Shell prompt 
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


/* Private header file(s) */
#include "pksh.h"


/* Change the prompt */
void pkshprompt (char * interface)
{
  Char Prompt [256];
  char * prompt = NULL;

  int i;
  int len;

  if (interface)
    {
      prompt = calloc (strlen (progname) + strlen (interface) + 200, 1);
      sprintf (prompt, "%%S%s@%s %%!>%%s ", progname, interface);
    }
  else
    {
      prompt = calloc (strlen (progname) + 200, 1);
      sprintf (prompt, "%%S%s %%!>%%s ", progname);
    }

  len = strlen (prompt);
  for (i = 0; i <= len; i ++)
    Prompt [i] = prompt [i];

  free (prompt);

  setcopy (STRprompt, Strsave (Prompt), VAR_READWRITE);
}
