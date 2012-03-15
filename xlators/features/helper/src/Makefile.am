xlator_LTLIBRARIES = helper.la
xlatordir = $(libdir)/glusterfs/$(PACKAGE_VERSION)/xlator/features

helper_la_LDFLAGS = -module -avoidversion

helper_la_SOURCES = helper.c
helper_la_LIBADD = $(top_builddir)/libglusterfs/src/libglusterfs.la

noinst_HEADERS = helper.h $(top_builddir)/xlators/lib/src/libxlator.h

AM_CFLAGS = -fPIC -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE -Wall -fno-strict-aliasing -D$(GF_HOST_OS) \
        -I$(top_srcdir)/libglusterfs/src -I$(top_srcdir)/xlators/lib/src $(GF_CFLAGS) -shared -nostartfiles

CLEANFILES =

