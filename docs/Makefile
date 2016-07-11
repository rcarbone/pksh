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
# Docs Makefile
#

TARGETS=pksh.txt pksh.html

all: ${TARGETS}

pksh.txt: pksh.1
	@echo "Converting $< to ASCII format..."
	@groff -mandoc -Tascii $< | sed 's/_//g' | sed 's/[ -~]//g' > $@
	@echo "$@ done!"


pksh.html: pksh.1
	@echo "Converting $< to HTML format  .... Please wait"
	@man2html $< > $@
	@echo "$@ done!"

clean:
	@rm -f *~ '#*'

distclean: clean
	@rm -f ${TARGETS}
