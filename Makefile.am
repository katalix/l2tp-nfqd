AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = -I m4

AM_CFLAGS = -I. -I./include -Wall -Werror -Wno-strict-aliasing -fPIC
AM_LDFLAGS =

if NFQ_DEBUG
AM_CFLAGS += -g -ggdb -DDEBUG
else
AM_CFLAGS += -DNDEBUG
endif

AM_CPPFLAGS    = $(LIBMNL_CFLAGS)
AM_CPPFLAGS   += $(LIBNFQUEUE_CFLAGS)

LDADD  = $(LIBMNL_LIBS)
LDADD  += $(LIBNFQUEUE_LIBS)

sbin_PROGRAMS = l2tp-nfqd
l2tp_nfqd_SOURCES = src/main.c \
	src/l2tp_nfq.c \
	src/l2tp_nfq.h

pkgconfigdir = $(libdir)/pkgconfig
nodist_pkgconfig_DATA = l2tp-nfqd.pc

pkginclude_HEADERS = include/l2tp-nfqd.h

noinst_PROGRAMS = l2tp_nfq_test
l2tp_nfq_test_SOURCES = test/l2tp_nfq_test.c

EXTRA_DIST  = VERSION CHANGES LICENSE l2tp-nfqd.pc.in
EXTRA_DIST += bootstrap

clean-local:
	rm -f l2tp-nfqd.pc

l2tp-nfqd.pc : l2tp-nfqd.pc.in
	sed -e 's![@]prefix[@]!$(prefix)!g' \
		-e 's![@]exec_prefix[@]!$(exec_prefix)!g' \
		-e 's![@]includedir[@]!$(pkgincludedir)!g' \
		-e 's![@]libdir[@]!$(pkglibdir)!g' \
		-e 's![@]PACKAGE_VERSION[@]!$(PACKAGE_VERSION)!g' \
		$^ > $@
