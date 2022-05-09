/*
 * pksh - The Packet Shell
 *
 * R. Carbone (rocco@tecsiel.it)
 * 2003, 2008-2009, 2022
 *
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 */


/* Project header */
#include "pksh.h"


/* Identifiers */
#define NAME         "help"
#define BRIEF        "Help [builtin] If builtin is specified, print out help on it, otherwise print out the list of extensions"
#define SYNOPSIS     "help [options]"
#define DESCRIPTION  "No description yet"

/* Public variable */
pksh_cmd_t cmd_help = { NAME, BRIEF, SYNOPSIS, DESCRIPTION, pksh_help };


/* Constants */
#define HELPINDENT  10


/* GNU short options */
enum
{
  /* Startup */
  OPT_HELP     = 'h',
  OPT_QUIET    = 'q',

  /* List */
  OPT_BUILTINS = 'b',
  OPT_LIST     = 'l'
};


/* GNU long options */
static struct option lopts [] =
{
  /* Startup */
  { "help",     no_argument, NULL, OPT_HELP     },
  { "quiet",    no_argument, NULL, OPT_QUIET    },

  { "builtins", no_argument, NULL, OPT_BUILTINS },
  { "list",     no_argument, NULL, OPT_LIST     },

  { NULL,       0,           NULL, 0            }
};


/* The [help] builtin */
static void help_builtins (bool quiet)
{
  if (! quiet)
    {
      char ** names = cmd_names ();

      printf ("The following commands were implemented, as extensions to the native [tcsh] builtins:\n\n");

      args_print_rows (names, tcsh_screen_cols ());
      argsclear (names);
    }
}


/* The [help list] builtin */
static void help_list (bool quiet)
{
  unsigned i;
  for (i = 0; ! quiet && i < cmd_size (); i ++)
    {
      pksh_cmd_t * cmd = cmd_lookup (i);
      printf ("%-*s\t%s\n", HELPINDENT, cmd -> name, cmd -> brief);
    }
}


static void print_help (pksh_cmd_t * cmd, bool man, bool quiet)
{
  if (! quiet)
    {
      if (! man)
	printf ("%-*s\t%s.\n", HELPINDENT, cmd -> name, cmd -> brief);
      else
	{
	  printf ("NAME\n");
	  printf ("\t");
	  printf ("%s - %s\n", cmd -> name, cmd -> brief);
	  printf ("\n");

	  printf ("SYNOPSIS\n");
	  printf ("\t");
	  printf ("%s\n", cmd -> synopsis);
	  printf ("\n");

	  if (cmd -> description)
	    {
	      printf ("DESCRIPTION\n");
	      printf ("\t");
	      printf ("%s\n", cmd -> description);
	      printf ("\n");
	    }
	}
    }
}


/* Display the syntax */
static void usage (char * name, char * synopsis, char * help, struct option * options)
{
  /* longest option name */
  unsigned n = optmax (options);

  printf ("Startup:\n");
  usage_item (options, n, OPT_HELP,     "show this help message and exit");
  usage_item (options, n, OPT_QUIET,    "run quietly");
  printf ("\n");

  printf ("Documentation:\n");
  usage_item (options, n, OPT_BUILTINS, "list all implemented extensions");
  usage_item (options, n, OPT_LIST,     "list all implemented extensions and a brief description");
}


/* The [help] command */
int pksh_help (int argc, char * argv [])
{
  char * progname = basename (argv [0]);
  char * sopts    = optlegitimate (lopts);

  /* Variables that are set according to the specified options */
  bool quiet      = false;

  /* Variables that are set according to the specified options */
  bool man        = true;
  int rc          = 0;
  int option;

  /* Lookup for the command in the static table of registered extensions */
  if (! cmd_by_name (progname))
    {
      printf ("%s: Command [%s] not found.\n", progname, progname);
      return -1;
    }

  /* Parse command line options */
  optind = 0;
  optarg = NULL;
  argv [0] = progname;
  while ((option = getopt_long (argc, argv, sopts, lopts, NULL)) != -1)
    {
      switch (option)
	{
	default: if (! quiet) printf ("Try '%s --help' for more information.\n", progname); return 1;

	  /* Startup */
	case OPT_HELP:     usage (progname, NULL, NULL, lopts); return 0;
	case OPT_QUIET:    quiet = true;                        break;

	  /* List */
	case OPT_BUILTINS: help_builtins (quiet);               return 0;
	case OPT_LIST:     help_list (quiet);                   return 0;
	}
    }

  /* Process all given arguments */
  if (optind < argc)
    {
      char ** notfound = NULL;
      char ** nf;
      while (optind < argc)
	{
	  pksh_cmd_t * cmd = cmd_by_name (argv [optind]);
	  if (cmd)
	    print_help (cmd, man, quiet);
	  else
	    notfound = argsmore (notfound, argv [optind]);

	  optind ++;
	}
      if (notfound)
	rc = 1;
      nf = notfound;
      if (nf)
	while (! quiet && * nf)
	  printf ("%s: builtin [%s] not found.\n", progname, * nf ++);
      argsclear (notfound);
    }
  else
    help_builtins (quiet);

  /* Bye bye! */
  return rc;
}
