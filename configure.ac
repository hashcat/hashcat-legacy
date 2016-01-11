AC_PREREQ([2.68])
AC_INIT([hashcat], [2.0.1], [atom@hashcat.net])
AC_CANONICAL_TARGET
AC_CANONICAL_HOST
AC_CANONICAL_SYSTEM
AC_CONFIG_SRCDIR([include/rp.h])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE

# Checks for programs.
AC_PROG_AWK
AC_PROG_CC
AC_PROG_CXX
AC_PROG_INSTALL
AC_PROG_MAKE_SET

AC_ARG_ENABLE([xop], AS_HELP_STRING([--enable-xop], [Enable XOP optimization]))

AS_IF([test "x$enable_xop" = "xyes"], [
  xop_enabled=true
  AC_DEFINE(XOP_ENABLED)
  AH_TEMPLATE(XOP_ENABLED, [define if building with XOP optimization enabled])
])

AM_CONDITIONAL(XOP_ENABLED, test "x$xop_enabled" = xtrue)

AC_ARG_ENABLE([osx], AS_HELP_STRING([--enable-osx], [force cpu to 64bit]))

AS_IF([test "x$enable_osx" = "xyes"], [osx_enabled=true])

case "$host_cpu" in
	amd64)
		cpu_amd64=true
		AC_DEFINE(CPU_AMD64)
		AH_TEMPLATE(CPU_AMD64, [define if building for amd64])
		;;
	x86_64)
		cpu_x86_64=true
		AC_DEFINE(CPU_X86_64)
		AH_TEMPLATE(CPU_X86_64, [define if building for x86_64])
		;;
	i*86)
		if test "$osx_enabled" = true
		then
			cpu_x86_64=true
			AC_DEFINE(CPU_X86_64)
			AH_TEMPLATE(CPU_X86_64, [define if building for x86_64])
		else
			cpu_x86=true
			AC_DEFINE(CPU_X86)
			AH_TEMPLATE(CPU_X86, [define if building for x86])
		fi
		;;
esac

AM_CONDITIONAL(CPU_AMD64, test "x$cpu_amd64" = xtrue)
AM_CONDITIONAL(CPU_X86_64, test "x$cpu_x86_64" = xtrue)
AM_CONDITIONAL(CPU_X86, test "x$cpu_x86" = xtrue)

case "$host_os" in
	*linux*)
		host_linux=true
		AC_DEFINE(LINUX_OS)
		AH_TEMPLATE(LINUX_OS, [define if building for linux])
		AC_CHECK_LIB(pthread, pthread_create,, [AC_MSG_ERROR([required library pthread missing (libpthread)])])
		;;
	*darwin*)
		host_darwin=true
		AC_DEFINE(DARWIN_OS)
		AH_TEMPLATE(DARWIN_OS, [define if building for darwin])
		AC_CHECK_LIB(pthread, pthread_create,, [AC_MSG_ERROR([required library pthread missing (libpthread)])])
		;;
	*mingw*)
		host_windows=true
		AC_DEFINE(WINDOWS_OS)
		AH_TEMPLATE(WINDOWS_OS, [define if building for windows])
		;;
esac

AM_CONDITIONAL(LINUX_OS, test "x$host_linux" = xtrue)
AM_CONDITIONAL(DARWIN_OS, test "x$host_darwin" = xtrue)
AM_CONDITIONAL(WINDOWS_OS, test "x$host_windows" = xtrue)

# Checks for libraries.
AC_CHECK_LIB(m, cos,, [AC_MSG_ERROR([required library math missing (libm)])])
AC_CHECK_LIB(gmp, __gmpz_init,, [AC_MSG_ERROR([required library gmp not found (libgmp)])])

# Checks for header files.
AC_CHECK_HEADERS([stdint.h stdlib.h string.h sys/ioctl.h sys/time.h termio.h termios.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_INT8_T
AC_TYPE_SIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([gettimeofday memset select strchr strdup strerror strrchr strstr])

AC_CONFIG_FILES([
	Makefile
	src/Makefile
	docs/Makefile
	masks/Makefile
	tables/Makefile
	salts/Makefile
	rules/Makefile
	tools/Makefile
	charsets/Makefile])

AC_OUTPUT
