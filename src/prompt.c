/*
 * pksh - The Packet Shell
 *
 * R. Carbone (rocco@tecsiel.it)
 * 2003, 2008-2009, 2022
 *
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * How to manage the Packet Shell prompt
 */


/* tcsh header file(s) */
#include "sh.h"

/* Project header */
#include "pksh.h"


/* Change the prompt */
void pksh_prompt (char * interface)
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
