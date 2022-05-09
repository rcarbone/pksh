#
# pksh - The Packet Shell
#
# R. Carbone (rocco@tecsiel.it)
# 2003, 2008-2009, 2022
#
# SPDX-License-Identifier: BSD-2-Clause-FreeBSD
#

# The name of the game
PACKAGE  = pksh

# Root installation directory
INSTDIR  = /usr/local/${PACKAGE}

# The list of directories where to make something
SUBDIRS += src
SUBDIRS += shell

# The main target is responsible to recursively scan subdirectories and build all the modules
all: ${PACKAGE}/config.status ${SUBDIRS}
	@for dir in ${SUBDIRS} ; do \
           if [ -d $$dir ] ; then \
             if [ -f $$dir/Makefile ] ; then \
               echo "Making everything in [$$dir] ..." ; \
               make -C $$dir -s --no-print-directory $@ ; \
             fi ; \
           else \
             echo "Warning: missing directory [$$dir]" ; \
           fi \
         done

${PACKAGE}/config.status:
	@./configure

# Cleanup rules
clean:
	@rm -f *~
	@for dir in ${SUBDIRS} ; do \
           if [ -d $$dir ] ; then \
             if [ -f $$dir/Makefile ] ; then \
               make -C $$dir -s --no-print-directory $@ ; \
             fi \
           fi \
         done

distclean: clean
	@rm -rf ${PACKAGE}/

# Targets that are eventually handled by recursive Makefile(s)
%:
	@for dir in ${SUBDIRS} ; do \
           if [ -d $$dir ] ; then \
             echo $$dir; \
             if [ -f $$dir/Makefile ] ; then \
               make -C $$dir -s --no-print-directory $@ ; \
               echo ; \
             fi ; \
           else \
             echo "Warning: missing directory [$$dir]" ; \
           fi \
         done

# Fake targets
.PHONY: all clean distclean ${SUBDIRS}
