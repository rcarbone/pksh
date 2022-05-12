/*
 * pksh - The Packet Shell
 *
 * R. Carbone (rocco@tecsiel.it)
 * 2008-2009, 2022
 *
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 */


/* Project header */
#include "pksh.h"


/* Inline sources */
#include "missing.c"


/* Commands */
static void try_commands_all (int argc, char * argv [])
{
#if defined(ROCCO)
  cmd_size ();
  cmd_names ();
  cmd_by_name (NULL);
  cmd_lookup (0);
  cmd_by_index (0);
  cmd_maxname ();
#endif /* ROCCO */
}


/* Internal */
static void try_pksh_internal_all (int argc, char * argv [])
{
  tcsh_builtins (0, NULL);
}


/* Helpers */
static void try_pksh_helpers_all (int argc, char * argv [])
{
  pksh_init (NULL, 0);
  pksh_prompt (NULL);

  pksh_help (argc, argv);
  pksh_pkhelp (argc, argv);

  pksh_about (argc, argv);
  pksh_version (argc, argv);
  pksh_license (argc, argv);
}


/* Network Interfaces */
static void try_pksh_interfaces_all (int argc, char * argv [])
{
  pksh_pkdev (argc, argv);
  pksh_pkopen (argc, argv);
  pksh_pkclose (argc, argv);
  pksh_pkenable (argc, argv);
  pksh_pkstatus (argc, argv);
  pksh_pkuptime (argc, argv);
  pksh_pkfilter (argc, argv);
  pksh_pkswap (argc, argv);
}


/* Viewers */
static void try_pksh_viewers_all (int argc, char * argv [])
{
  pksh_packets (argc, argv);
  pksh_bytes (argc, argv);
  pksh_protocols (argc, argv);
#if defined(ROCCO)
  pksh_services (argc, argv);
#endif /* ROCCO */
  pksh_throughput (argc, argv);
  pksh_pkhosts (argc, argv);
  pksh_pkarp (argc, argv);
  pksh_pklast (argc, argv);
  pksh_pkwho (argc, argv);
  pksh_pkfinger (argc, argv);
}


/*
 * Does nothing, but tries to link static library.
 *
 * The functions have been written only to test
 * if a binary program can be generated at compile time.
 *
 * They will never be executed, so there is no need to check for failures.
 */
int main (int argc, char * argv [])
{
  printf ("This program does nothing, but it only tests if link works at compile time. Bye bye!\n");

  if (argc == 0)
    {
      /* Never executed, so no check is done about possible failures */
      try_pksh_internal_all (argc, argv);
      try_commands_all (argc, argv);

      try_pksh_helpers_all (argc, argv);
      try_pksh_interfaces_all (argc, argv);
      try_pksh_viewers_all (argc, argv);
    }

  /* Bye bye! */
  return 0;
}
