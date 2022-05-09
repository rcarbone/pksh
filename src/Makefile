#
# pksh - The Packet Shell
#
# R. Carbone (rocco@tecsiel.it)
# 2003, 2008-2009, 2022
#
# SPDX-License-Identifier: BSD-2-Clause-FreeBSD
#

# Project directories
ROOTDIR   = ..

# Level 1 and more
INCDIR    = ${ROOTDIR}/include
LIBDIR    = ${ROOTDIR}/3rdparty
RLIBCDIR  = ${LIBDIR}/rlibc/src
PKSHDIR   = ${ROOTDIR}/shell

# C source files
MAINSRCS += try-link.c

# rlibc
LIBSRCS  += glob.c
LIBSRCS  += interval.c
LIBSRCS  += list.c
LIBSRCS  += hash.c

# tcsh-specific
LIBSRCS  += tcsh-wrap.c
LIBSRCS  += init.c
LIBSRCS  += prompt.c

# Support
LIBSRCS  += cache.c
LIBSRCS  += commands.c
LIBSRCS  += datalinks.c
LIBSRCS  += decoders.c
LIBSRCS  += ettercap.c
LIBSRCS  += interface.c
LIBSRCS  += render.c
LIBSRCS  += sort.c
LIBSRCS  += vendor.c

# Helpers
LIBSRCS  += pkhelp.c
LIBSRCS  += help.c
LIBSRCS  += about.c
LIBSRCS  += license.c
LIBSRCS  += version.c

# Network Interfaces
LIBSRCS  += pkdev.c
LIBSRCS  += open.c
LIBSRCS  += close.c
LIBSRCS  += enable.c
LIBSRCS  += status.c
LIBSRCS  += uptime.c
LIBSRCS  += filter.c
LIBSRCS  += swap.c

# Viewers
LIBSRCS  += packets.c
LIBSRCS  += bytes.c
# LIBSRCS  += services.c
LIBSRCS  += throughput.c
LIBSRCS  += protocols.c
LIBSRCS  += hosts.c
LIBSRCS  += arp.c
LIBSRCS  += last.c
LIBSRCS  += who.c
LIBSRCS  += finger.c

# The name of the games
LIBNAME   = pksh
PROGRAMS += ${MAINSRCS:%.c=%}

# All C source files
SRCS      = ${LIBSRCS} ${MAINSRCS}

# All libraries
STLIB     = lib${LIBNAME}.a
# SHLIB     = ${STLIB:%.a=%.so}

# All targets
TARGETS   = ${STLIB} ${SHLIB} ${PROGRAMS}

# Object and depend files
LIBOBJS   = ${LIBSRCS:%.c=%.o}
MAINOBJS  = ${MAINSRCS:%.c=%.o}
OBJS      = ${LIBOBJS} ${MAINOBJS}
DEPS      = ${SRCS:%.c=%.M}

# C/C++ Compilers and flags
INCLUDES  = -I./
INCLUDES += ${INCLUDE}
CC        = gcc
AR        = ar
LD        = gcc
CFLAGS   += -g -Wall -D_DEFAULT_SOURCE
CFLAGS   += -fPIC
CFLAGS   += -fno-diagnostics-color
CFLAGS   += ${INCLUDES}
ARFLAGS   = rv
LDFLAGS   =

# External libraries
INCLUDE  += -I${INCDIR}
INCLUDE  += -I${RLIBCDIR}
INCLUDE  += -I${PKSHDIR}

# User and System Libraries
USRLIBS  += ${STLIB}
USRLIBS  += ${RLIBCDIR}/librlibc.a
SYSLIBS  += -lm -lpcap -lpthread

# The main target is responsible to make all
all: oui2c nic.h ettercap.h ${TARGETS}

# Targets for the NIC vendors table
oui2c: oui2c.c
	@echo "=*= making program $@ =*="
	@${CC} -g $< -o $@

# Download the NIC vendor table from the Internet
#
# Latest version as of May 2022 is located here:
#   https://standards-oui.ieee.org/oui/oui.txt
#
# Another list of EtherTypes is maintained by
# Michael A. Patton and is accessible at:
#   http://www.cavebear.com/CaveBear/Ethernet
#
oui.txt:
	@echo "Fetching NIC vendor table from the Internet..."
	@wget -c https://standards-oui.ieee.org/oui/oui.txt
	@dos2unix oui.txt

# Convert the [oui] text file to a C variable
nic.h: oui.txt oui2c
	@echo "=*= making table $@ =*="
	@./oui2c > $@

# Targets for the [ettercap] passive OS fingerprint database
ettercap2c: ettercap2c.c
	@echo "=*= making program $@ =*="
	@${CC} -g $< -o $@

# Download the [ettercap] passive OS fingerprint database from the Internet
etter.finger.os:
	@echo "Fetching 'ettercap' passive OS fingerprint database from the Internet..."
	@wget -c 'https://github.com/Ettercap/ettercap/blob/master/share/etter.finger.os'

# Convert the [etter.finger.os] text file to a C variable
ettercap.h: etter.finger.os ettercap2c
	@echo "=*= making table $@ =*="
	@./ettercap2c > $@

# Static library
${STLIB}: ${LIBOBJS}
	@echo "=*= making static library $@ =*="
	@${AR} ${ARFLAGS} $@ $^ 1> /dev/null 2>& 1

# Shared library
${SHLIB}: ${LIBOBJS}
	@echo "=*= making shared library $@ =*="
	@${CC} -shared $^ ${USRLIBS} ${SYSLIBS} -o $@

# Binary programs
%: %.o ${USRLIBS}
	@echo "=*= making program $@ =*="
	@${LD} ${LDFLAGS} $^ ${SYSLIBS} -o $@

# Cleanup rules
clean:
	@rm -f oui2c ettercap2c
	@rm -f ${TARGETS}
	@rm -f ${OBJS}
	@rm -f *~

distclean: clean
	@rm -f ${DEPS}

hclean:
	@rm -f nic.h
	@rm -f ettercap.h

# How to make an object file from a C source
%.o: %.c
	@echo "=*= making object $@ =*="
	@${CC} -c ${CFLAGS} $<

# How to make a depend file from a C source
%.M: %.c
	@-${CC} -MM ${INCLUDES} $< -o $@

-include ${DEPS}

# External libraries
${RLIBCDIR}/librlibc.a:
	@make -C ${RLIBCDIR}

.DEFAULT:
	@echo "No rule to make $@"
