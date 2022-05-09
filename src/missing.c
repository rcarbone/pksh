/*
 * pksh - The Packet Shell
 *
 * R. Carbone (rocco@tecsiel.it)
 * 2003, 2008-2009, 2022
 *
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * It defines constants/types/variables/functions required to link
 */


/* Project header */
#include "pksh.h"


/* constants/types/variables/functions required to link */

#define Char char

struct command;
struct varent { int a; };

/* variables/functions required to link */
char * progname = PKSH_PACKAGE;

Char STRprompt [256];
Char STRstatus [256];
Char STR1 [256];
int TermH;
int TermV;

struct varent shvhed;

/* Dummy functions required to link */
int xprintf (const char * s, ...)                    { return 0; }
char * s_strsave (char * s)                          { return s; }
void setcopy (const char * a, const char * b, int n) {           }

char ** blk2short (char ** a)                        { return a; }
const char * short2str (const Char * a)              { return a; }
char ** short2blk (Char ** a)                        { return NULL; }
int blklen (Char ** a)                               { return 0; }

struct varent * adrof1 (const Char * a, struct varent * b) { return NULL; }


void doset (Char ** a, struct command * b)           { };
void unset (Char ** a, struct command * b)           { };
void docomplete (Char ** a, struct command * b)      { };
void doecho (Char ** a, struct command * b)          { };
