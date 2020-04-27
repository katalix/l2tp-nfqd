#
# Autoconf script for the Katalix User Space Library
#
AC_PREREQ([2.57])
AC_INIT([l2tp-nfq], m4_esyscmd([cat ./VERSION | tr -d '\n']), [oss@prol2tp.com])
AM_INIT_AUTOMAKE([-Wall foreign subdir-objects])

# Set CFLAGS empty if user didn't set it -- this avoids autoconf defaulting to
# -O2 for gcc, which breaks profiling and gdb usage
: ${CFLAGS=""}
LT_INIT
PKG_PROG_PKG_CONFIG
PKG_CHECK_MODULES([LIBMNL], [libmnl])
PKG_CHECK_MODULES([LIBNFQUEUE], [libnetfilter_queue])

AC_CONFIG_FILES([Makefile])
AC_CONFIG_SRCDIR([src/l2tp_nfq.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])

AM_CONDITIONAL(CROSS_COMPILING, [test "x$cross_compiling" != "xno"])

# Configurable options
AM_CONDITIONAL(NFQ_DEBUG, [test "x$enable_debug" = "xyes"])
AC_ARG_ENABLE([debug],
	[AS_HELP_STRING([--enable-debug], [enable debug and turn on all debug messages])],
	[DEBUG_CONFFLAGS="--enable-debug"])
AC_SUBST([DEBUG_CONFFLAGS])

AC_SUBST([NFQ_VERSION], [$VERSION])

# Checks for programs.
AC_PROG_CC

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h limits.h syslog.h netinet/in.h netinet/un.h netinet/ip.h arpa/inet.h stdarg.h stddef.h stdint.h stdlib.h stdbool.h string.h sys/ioctl.h sys/socket.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_UINT32_T

# Checks for library functions.
AC_FUNC_FORK
AC_CHECK_FUNCS([memset strerror])

AC_OUTPUT
