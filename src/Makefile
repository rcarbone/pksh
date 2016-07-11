#
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
#                      _        _
#                _ __ | | _____| |__
#               | '_ \| |/ / __| '_ \
#               | |_) |   <\__ \ | | |
#               | .__/|_|\_\___/_| |_|
#               |_|
#
#              'pksh', the Packet Shell
#
#              (C) Copyright 2008-2009
#     Rocco Carbone <rocco /at/ ntop /dot/ org>
#
#  Released under the terms of GNU General Public License
#  at version 3;  see included COPYING file for details
#
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
#
# A develop only makefile, not a production one,
# which is only used to compile objects on place
# before their inclusion in the shell.
#

# the name of the game
PACKAGE = pksh

# tcsh source identifiers
TCSHVERSION=6.16.00
TCSH=tcsh-${TCSHVERSION}

CC      = gcc
CFLAGS  = -g -I../${PACKAGE}-${TCSH} -Wall
LDFLAGS =

SUPPORT = args.c     cache.c datalinks.c decoders.c ettercap.c \
          fmemdmp.c  glob.c  hash.c      init.c     interface.c \
          interval.c list.c  prompt.c    render.c   sort.c \
          vendor.c   wrapper.c

ADMIN   = pkclose.c pkdev.c    pkenable.c pkfilter.c pkhelp.c \
          pkopen.c  pkstatus.c pkswap.c   pkuptime.c

VIEWS   = bytes.c  packets.c pkarp.c      pkfinger.c  pkhosts.c \
          pklast.c pkwho.c   throughput.c protocols.c services.c

OTHERS  = stupid.c

BUILTIN = ${ADMIN} ${VIEWS} ${OTHERS}

SRCS    = ${SUPPORT} ${BUILTIN}
OBJS    = $(patsubst %.c, %.o, ${SRCS})

TARGETS = ${OBJS}

%.o: %.c pksh.h
	@echo "=*= making object $@ =*="
	@${CC} -c ${CFLAGS} $<

all: nic.h ettercap.h ${TARGETS}

# targets for the NIC vendors table
oui2c: oui2c.c
	@echo "=*= making program $@ =*="
	@${CC} -g $< -o $@

# download the NIC vendor table from the Internet
#
# another list of EtherTypes is maintained by
# Michael A. Patton and is accessible at:
#
#    <http://www.cavebear.com/CaveBear/Ethernet/>

oui.txt:
	@echo "Fetching NIC vendor table from the Internet..."
	@wget -c http://standards.ieee.org/regauth/oui/oui.txt

# convert the file to a C variable
nic.h: oui.txt oui2c
	@echo "=*= making table $@ =*="
	@./oui2c > $@

# targets for the 'ettercap' passive OS fingerprint database
ettercap2c: ettercap2c.c
	@echo "=*= making program $@ =*="
	@${CC} -g $< -o $@

# download the 'ettercap' passive OS fingerprint database from the Internet
etter.finger.os:
	@echo "Fetching 'ettercap' passive OS fingerprint database from the Internet..."
	@wget -c 'http://ettercap.cvs.sourceforge.net/*checkout*/ettercap/ettercap_ng/share/etter.finger.os'

# convert the file to a C variable
ettercap.h: etter.finger.os ettercap2c
	@echo "=*= making table $@ =*="
	@./ettercap2c > $@

clean:
	@rm -f oui2c ettercap2c
	@rm -f ${OBJS} *~ '#*'

distclean: clean
	@rm -f oui2c nic.h
	@rm -f ettercap2c ettercap.h
