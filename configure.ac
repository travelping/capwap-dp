dnl ##
dnl ##  PROLOG
dnl ##

dnl #   standard Autoconf prolog

AC_PREREQ(2.59)

AC_INIT(capwap-dp, [1.0])
AC_CONFIG_SRCDIR(src/capwap-dp.c)
AC_CONFIG_AUX_DIR(config)
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE(1.9)

AC_SRCDIR_PREFIX(srcdir_prefix)
AC_HEADLINE(dnl
TPOSS CAPWAP Data Path, dnl
[Copyright (c) 2014 Travelping GmbH <info@travelping.com>])
AM_CONFIG_HEADER(config.h)
AC_PREFIX_DEFAULT(/usr)
AC_PLATFORM(PLATFORM)

dnl ##
dnl ##  BUILD TOOLS
dnl ##

AC_MSG_PART(Build Tools)

AC_CANONICAL_HOST
AC_PROG_CC
AC_PROG_CPP
AC_DISABLE_SHARED
AC_PROG_INSTALL
AC_SET_MAKE
AC_CHECK_DEBUGGING

AC_MSG_PART(Configure libtool)
AM_PROG_LIBTOOL

dnl ##
dnl ##   MANDATORY PLATFORM ENVIRONMENT
dnl ##

AC_MSG_PART(Mandatory Platform Environment)

AC_HEADER_STDC
AC_ISC_POSIX
AC_C_BIGENDIAN

AC_HEADER_STDC
AC_CHECK_HEADERS([stdarg.h])
AC_CHECK_FUNCS(strcpy strdup strcmp free malloc open read close fprintf)
AC_CHECK_LIBM

AM_MAINTAINER_MODE

AC_HEADER_ASSERT

AC_MSG_PART(required libraries)
AC_CHECK_LIB([ev], [event_init],, AC_MSG_ERROR(Required library ev missing))
AC_CHECK_LIB([pthread], [pthread_create],, AC_MSG_ERROR(Required library pthread missing))
PKG_CHECK_MODULES([URCU], [liburcu],, AC_MSG_ERROR(Required library urcu missing))
PKG_CHECK_MODULES([URCUCDS], [liburcu-cds],, AC_MSG_ERROR(Required library urcu-cds missing))

ERL_CRASH_DUMP=/dev/null
EIBASE="`erl -noshell -noinput -eval 'io:format (\"~s\", [[ code:lib_dir (erl_interface) ]])' -s erlang halt`"
AC_SUBST([EIBASE])

ERTSBASE="`erl -noshell -noinput -eval 'io:format (\"~s\", [[ \"/\" ++ filename:join (lists:reverse ([ \"erts-\" ++ erlang:system_info (version) | tl (lists:reverse (string:tokens (code:lib_dir (), \"/\"))) ])) ]]).' -s erlang halt `"
AC_SUBST([ERTSBASE])

CPPFLAGS="$CPPFLAGS -I${EIBASE}/include -I${ERTSBASE}/include"
LDFLAGS="$LDFLAGS -L${EIBASE}/lib -L${ERTSBASE}/lib"

AC_CHECK_HEADER([erl_interface.h], [], [AC_MSG_ERROR([can't find erl_interface.h; under debian you need to install erlang-src])], [])
AC_CHECK_LIB([ei], [ei_set_compat_rel], [], [AC_MSG_ERROR([can't find libei])], [])
AC_CHECK_LIB([erl_interface], [erl_compare_ext], [], [AC_MSG_ERROR([can't find liberl_interface])], [])

AC_CONFIG_FILES([
        Makefile
        src/Makefile
])

AC_OUTPUT
