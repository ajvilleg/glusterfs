xlator_LTLIBRARIES = hsrepl.la
xlatordir = $(libdir)/glusterfs/$(PACKAGE_VERSION)/xlator/features

hsrepl_la_LDFLAGS = -module -avoidversion

hsrepl_la_SOURCES = hsrepl.c
hsrepl_la_LIBADD = $(top_builddir)/libglusterfs/src/libglusterfs.la

noinst_HEADERS = hsrepl.h $(top_builddir)/xlators/lib/src/libxlator.h

AM_CFLAGS = -fPIC -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE -Wall -fno-strict-aliasing -D$(GF_HOST_OS) \
        -I$(top_srcdir)/libglusterfs/src -I$(top_srcdir)/xlators/lib/src $(GF_CFLAGS) -shared -nostartfiles

CLEANFILES =

