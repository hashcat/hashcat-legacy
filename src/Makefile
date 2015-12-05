##
## Author......: Jens Steube <jens.steube@gmail.com>
## License.....: MIT
##

##
##  Makefile for hashcat
##

##
## Detect number of processors
##

NPROCS   := 1
OS       := $(shell uname)

ifeq ($(OS),Linux)
  NPROCS := $(shell grep -c ^processor /proc/cpuinfo)
else ifeq ($(OS),Darwin)
  NPROCS := $(shell system_profiler | awk '/Number of CPUs/ {print $$4}{next;}')
endif

##
## Makefile flags
##

MAKEFLAGS += -l -j $(NPROCS) -rR --no-print-directory

ifneq ($(findstring clean,$(MAKECMDGOALS)),)
MAKEFLAGS += -j 1
endif

# -mstackrealign is required otherwise crashes on windows xp, see hashcat v0.41 and v0.42

CFLAGS  := -W -Wall -pipe -I include/ -O2 -s -fomit-frame-pointer -funroll-loops
#CFLAGS  := -W -Wall -pipe -I include/ -g
LDFLAGS :=

all: binaries

clean:
	rm -rf core out word hash release obj/* hashcat.pot hashcat-cli*

binaries: linux windows osx

osx: osx64
#linux: posix32 posix64 posixAVX posixAVX2 posixXOP
#windows: windows32 windows64 windowsAVX windowsAVX2 windowsXOP
linux: posix32 posix64 posixXOP
windows: windows32 windows64 windowsXOP

release:
	rm -rf release
	mkdir release
	cp -a charsets docs rules tables salts examples hashcat-cli*.bin hashcat-cli*.exe hashcat-cli64.app release/
	find release -type f -exec chmod 600 {} \;
	find release -type d -exec chmod 700 {} \;
	chmod 700 release/*.bin
	chmod 700 release/*.app
	unix2dos release/salts/*
	unix2dos release/rules/*
	unix2dos release/tables/*
	unix2dos release/docs/*
	unix2dos release/examples/*

##
## OSX64
##

DIR_OSX64      = obj
CC_OSX64       = i686-apple-darwin10-gcc
LIBGMP_OSX64   = /opt/hashcat-deps/gmp/osx64
CFLAGS_OSX64   = $(CFLAGS) -I$(LIBGMP_OSX64)/include -D__HC_x86_64__ -DPOSIX -DOSX -m64 -msse2 -fnested-functions -arch x86_64 -mmacosx-version-min=10.5
LDFLAGS_OSX64  = $(LDFLAGS) -L$(LIBGMP_OSX64)/lib -lm -lpthread  -mmacosx-version-min=10.5 -lgmp

osx64: hashcat-cli64.app

rules-osx64: rules-debug64.app

rules-debug64.app: $(DIR_OSX64)/rp.OSX.64.o src/rules-debug.c
	$(CC_OSX64) $(filter-out -s,$(CFLAGS_OSX64)) $(DIR_OSX64)/*.OSX.64.o src/rules-debug.c -o rules-debug64.app $(LDFLAGS_OSX64)

hashcat-osx64: hashcat-cli64.app

hashcat-cli64.app: $(DIR_OSX64)/tsearch.OSX.64.o $(DIR_OSX64)/rp.OSX.64.o $(DIR_OSX64)/engine.OSX.64.o src/hashcat-cli.c
	$(CC_OSX64) $(filter-out -s,$(CFLAGS_OSX64)) $(DIR_OSX64)/*.OSX.64.o src/hashcat-cli.c -o hashcat-cli64.app $(LDFLAGS_OSX64)

engine-osx64: $(DIR_OSX64)/engine.OSX.64.o

$(DIR_OSX64)/engine.OSX.64.o: $(DIR_OSX64)/common.OSX.64.o src/engine.c
	$(CC_OSX64) $(CFLAGS_OSX64) -c src/engine.c -o $(DIR_OSX64)/engine.OSX.64.o

rp-osx64: $(DIR_OSX64)/rp.OSX.64.o

$(DIR_OSX64)/rp.OSX.64.o: $(DIR_OSX64)/common.OSX.64.o src/rp.c
	$(CC_OSX64) $(CFLAGS_OSX64) -c src/rp.c -o $(DIR_OSX64)/rp.OSX.64.o

tsearch-osx64: $(DIR_OSX64)/tsearch.OSX.64.o

$(DIR_OSX64)/tsearch.OSX.64.o: $(DIR_OSX64)/common.OSX.64.o src/tsearch.c
	$(CC_OSX64) $(CFLAGS_OSX64) -c src/tsearch.c -o $(DIR_OSX64)/tsearch.OSX.64.o

common-osx64: $(DIR_OSX64)/common.OSX.64.o

$(DIR_OSX64)/common.OSX.64.o: src/common.c
	$(CC_OSX64) $(CFLAGS_OSX64) -c src/common.c -o $(DIR_OSX64)/common.OSX.64.o

##
## POSIX32
##

DIR_POSIX32      = obj
LIBGMP_POSIX32   = /opt/hashcat-deps/gmp/linux32
CC_POSIX32       = gcc
CFLAGS_POSIX32   = $(CFLAGS) -I$(LIBGMP_POSIX32)/include -D__HC_x86_32__ -DPOSIX -m32 -msse2
LDFLAGS_POSIX32  = $(LDFLAGS) -L$(LIBGMP_POSIX32)/lib -lm -lpthread -lgmp

posix32: hashcat-cli32.bin

rules-posix32: rules-debug32.bin

rules-debug32.bin: $(DIR_POSIX32)/rp.LINUX.32.o src/rules-debug.c
	$(CC_POSIX32) $(CFLAGS_POSIX32) $(DIR_POSIX32)/*.LINUX.32.o src/rules-debug.c -o rules-debug32.bin $(LDFLAGS_POSIX32)

hashcat-posix32: hashcat-cli32.bin

hashcat-cli32.bin: $(DIR_POSIX32)/tsearch.LINUX.32.o $(DIR_POSIX32)/rp.LINUX.32.o  $(DIR_POSIX32)/engine.LINUX.32.o src/hashcat-cli.c
	$(CC_POSIX32) $(CFLAGS_POSIX32) $(DIR_POSIX32)/*.LINUX.32.o src/hashcat-cli.c -o hashcat-cli32.bin $(LDFLAGS_POSIX32)

engine-posix32: $(DIR_POSIX32)/engine.LINUX.32.o

$(DIR_POSIX32)/engine.LINUX.32.o: $(DIR_POSIX32)/common.LINUX.32.o src/engine.c
	$(CC_POSIX32) $(CFLAGS_POSIX32) -c src/engine.c -o $(DIR_POSIX32)/engine.LINUX.32.o

rp-posix32: $(DIR_POSIX32)/rp.LINUX.32.o

$(DIR_POSIX32)/rp.LINUX.32.o: $(DIR_POSIX32)/common.LINUX.32.o src/rp.c
	$(CC_POSIX32) $(CFLAGS_POSIX32) -c src/rp.c -o $(DIR_POSIX32)/rp.LINUX.32.o

tsearch-posix32: $(DIR_POSIX32)/tsearch.LINUX.32.o

$(DIR_POSIX32)/tsearch.LINUX.32.o: $(DIR_POSIX32)/common.LINUX.32.o src/tsearch.c
	$(CC_POSIX32) $(CFLAGS_POSIX32) -c src/tsearch.c -o $(DIR_POSIX32)/tsearch.LINUX.32.o

common-posix32: $(DIR_POSIX32)/common.LINUX.32.o

$(DIR_POSIX32)/common.LINUX.32.o: src/common.c
	$(CC_POSIX32) $(CFLAGS_POSIX32) -c src/common.c -o $(DIR_POSIX32)/common.LINUX.32.o

##
## POSIX64
##

DIR_POSIX64      = obj
LIBGMP_POSIX64   = /opt/hashcat-deps/gmp/linux64
CC_POSIX64       = gcc
CFLAGS_POSIX64   = $(CFLAGS) -I$(LIBGMP_POSIX64)/include -D__HC_x86_64__ -DPOSIX -m64 -msse2
LDFLAGS_POSIX64  = $(LDFLAGS) -L$(LIBGMP_POSIX64)/lib -lm -lpthread -lgmp

posix64: hashcat-cli64.bin

rules-posix64: $(DIR_POSIX64)/rp.LINUX.64.o

rules-debug64.bin: $(DIR_POSIX64)/rp.LINUX.64.o src/rules-debug.c
	$(CC_POSIX64) $(CFLAGS_POSIX64) $(DIR_POSIX64)/*.LINUX.64.o src/rules-debug.c -o rules-debug64.bin $(LDFLAGS_POSIX64)

hashcat-posix64: hashcat-cli64.bin

hashcat-cli64.bin: $(DIR_POSIX64)/tsearch.LINUX.64.o $(DIR_POSIX64)/rp.LINUX.64.o $(DIR_POSIX64)/engine.LINUX.64.o src/hashcat-cli.c
	$(CC_POSIX64) $(CFLAGS_POSIX64) $(DIR_POSIX64)/*.LINUX.64.o src/hashcat-cli.c -o hashcat-cli64.bin $(LDFLAGS_POSIX64)

engine-posix64: $(DIR_POSIX64)/engine.LINUX.64.o

$(DIR_POSIX64)/engine.LINUX.64.o: $(DIR_POSIX64)/common.LINUX.64.o src/engine.c
	$(CC_POSIX64) $(CFLAGS_POSIX64) -c src/engine.c -o $(DIR_POSIX64)/engine.LINUX.64.o

rp-posix64: $(DIR_POSIX64)/rp.LINUX.64.o

$(DIR_POSIX64)/rp.LINUX.64.o: $(DIR_POSIX64)/common.LINUX.64.o src/rp.c
	$(CC_POSIX64) $(CFLAGS_POSIX64) -c src/rp.c -o $(DIR_POSIX64)/rp.LINUX.64.o

tsearch-posix64: $(DIR_POSIX64)/tsearch.LINUX.64.o

$(DIR_POSIX64)/tsearch.LINUX.64.o: $(DIR_POSIX64)/common.LINUX.64.o src/tsearch.c
	$(CC_POSIX64) $(CFLAGS_POSIX64) -c src/tsearch.c -o $(DIR_POSIX64)/tsearch.LINUX.64.o

common-posix64: $(DIR_POSIX64)/common.LINUX.64.o

$(DIR_POSIX64)/common.LINUX.64.o: src/common.c
	$(CC_POSIX64) $(CFLAGS_POSIX64) -c src/common.c -o $(DIR_POSIX64)/common.LINUX.64.o

##
## POSIXAVX
##

DIR_POSIXAVX      = obj
LIBGMP_POSIXAVX   = /opt/hashcat-deps/gmp/linux64
CC_POSIXAVX       = gcc
CFLAGS_POSIXAVX   = $(CFLAGS) -I$(LIBGMP_POSIXAVX)/include -D__HC_AVX__ -DPOSIX -m64 -mavx
LDFLAGS_POSIXAVX  = $(LDFLAGS) -L$(LIBGMP_POSIXAVX)/lib -lm -lpthread -lgmp

posixAVX: hashcat-cliAVX.bin

rules-posixAVX: rules-debugAVX.bin

rules-debugAVX.bin: $(DIR_POSIXAVX)/rp.LINUX.AVX.o src/rules-debug.c
	$(CC_POSIXAVX) $(CFLAGS_POSIXAVX) $(DIR_POSIXAVX)/*.LINUX.AVX.o src/rules-debug.c -o rules-debugAVX.bin $(LDFLAGS_POSIXAVX)

hashcat-posixAVX: hashcat-cliAVX.bin

hashcat-cliAVX.bin: $(DIR_POSIXAVX)/tsearch.LINUX.AVX.o $(DIR_POSIXAVX)/rp.LINUX.AVX.o $(DIR_POSIXAVX)/engine.LINUX.AVX.o src/hashcat-cli.c
	$(CC_POSIXAVX) $(CFLAGS_POSIXAVX) $(DIR_POSIXAVX)/*.LINUX.AVX.o src/hashcat-cli.c -o hashcat-cliAVX.bin $(LDFLAGS_POSIXAVX)

engine-posixAVX: $(DIR_POSIXAVX)/engine.LINUX.AVX.o

$(DIR_POSIXAVX)/engine.LINUX.AVX.o: $(DIR_POSIXAVX)/common.LINUX.AVX.o src/engine.c
	$(CC_POSIXAVX) $(CFLAGS_POSIXAVX) -c src/engine.c -o $(DIR_POSIXAVX)/engine.LINUX.AVX.o

rp-posixAVX: $(DIR_POSIXAVX)/rp.LINUX.AVX.o

$(DIR_POSIXAVX)/rp.LINUX.AVX.o: $(DIR_POSIXAVX)/common.LINUX.AVX.o src/rp.c
	$(CC_POSIXAVX) $(CFLAGS_POSIXAVX) -c src/rp.c -o $(DIR_POSIXAVX)/rp.LINUX.AVX.o

tsearch-posixAVX: $(DIR_POSIXAVX)/tsearch.LINUX.AVX.o

$(DIR_POSIXAVX)/tsearch.LINUX.AVX.o: $(DIR_POSIXAVX)/common.LINUX.AVX.o src/tsearch.c
	$(CC_POSIXAVX) $(CFLAGS_POSIXAVX) -c src/tsearch.c -o $(DIR_POSIXAVX)/tsearch.LINUX.AVX.o

common-posixAVX: $(DIR_POSIXAVX)/common.LINUX.AVX.o

$(DIR_POSIXAVX)/common.LINUX.AVX.o: src/common.c
	$(CC_POSIXAVX) $(CFLAGS_POSIXAVX) -c src/common.c -o $(DIR_POSIXAVX)/common.LINUX.AVX.o

##
## POSIXAVX2
##

DIR_POSIXAVX2     = obj
LIBGMP_POSIXAVX2  = /opt/hashcat-deps/gmp/linux64
CC_POSIXAVX2      = gcc
CFLAGS_POSIXAVX2  = $(CFLAGS) -I$(LIBGMP_POSIXAVX2)/include -D__HC_AVX2__ -DPOSIX -m64 -mavx2
LDFLAGS_POSIXAVX2 = $(LDFLAGS) -L$(LIBGMP_POSIXAVX2)/lib -lm -lpthread -lgmp

posixAVX2: hashcat-cliAVX2.bin

rules-posixAVX2: rules-debugAVX2.bin

rules-debugAVX2.bin: $(DIR_POSIXAVX2)/rp.LINUX.AVX2.o src/rules-debug.c
	$(CC_POSIXAVX2) $(CFLAGS_POSIXAVX2) $(DIR_POSIXAVX2)/*.LINUX.AVX2.o src/rules-debug.c -o rules-debugAVX2.bin $(LDFLAGS_POSIXAVX2)

hashcat-posixAVX2: hashcat-cliAVX2.bin

hashcat-cliAVX2.bin: $(DIR_POSIXAVX2)/tsearch.LINUX.AVX2.o $(DIR_POSIXAVX2)/rp.LINUX.AVX2.o $(DIR_POSIXAVX2)/engine.LINUX.AVX2.o src/hashcat-cli.c
	$(CC_POSIXAVX2) $(CFLAGS_POSIXAVX2) $(DIR_POSIXAVX2)/*.LINUX.AVX2.o src/hashcat-cli.c -o hashcat-cliAVX2.bin $(LDFLAGS_POSIXAVX2)

engine-posixAVX2: $(DIR_POSIXAVX2)/engine.LINUX.AVX2.o

$(DIR_POSIXAVX2)/engine.LINUX.AVX2.o: $(DIR_POSIXAVX2)/common.LINUX.AVX2.o src/engine.c
	$(CC_POSIXAVX2) $(CFLAGS_POSIXAVX2) -c src/engine.c -o $(DIR_POSIXAVX2)/engine.LINUX.AVX2.o

rp-posixAVX2: $(DIR_POSIXAVX2)/rp.LINUX.AVX2.o

$(DIR_POSIXAVX2)/rp.LINUX.AVX2.o: $(DIR_POSIXAVX2)/common.LINUX.AVX2.o src/rp.c
	$(CC_POSIXAVX2) $(CFLAGS_POSIXAVX2) -c src/rp.c -o $(DIR_POSIXAVX2)/rp.LINUX.AVX2.o

tsearch-posixAVX2: $(DIR_POSIXAVX2)/tsearch.LINUX.AVX2.o

$(DIR_POSIXAVX2)/tsearch.LINUX.AVX2.o: $(DIR_POSIXAVX2)/common.LINUX.AVX2.o src/tsearch.c
	$(CC_POSIXAVX2) $(CFLAGS_POSIXAVX2) -c src/tsearch.c -o $(DIR_POSIXAVX2)/tsearch.LINUX.AVX2.o

common-posixAVX2: $(DIR_POSIXAVX2)/common.LINUX.AVX2.o

$(DIR_POSIXAVX2)/common.LINUX.AVX2.o: src/common.c
	$(CC_POSIXAVX2) $(CFLAGS_POSIXAVX2) -c src/common.c -o $(DIR_POSIXAVX2)/common.LINUX.AVX2.o

##
## POSIXXOP
##

DIR_POSIXXOP      = obj
LIBGMP_POSIXXOP   = /opt/hashcat-deps/gmp/linux64
CC_POSIXXOP       = gcc
CFLAGS_POSIXXOP   = $(CFLAGS) -I$(LIBGMP_POSIXXOP)/include -D__HC_XOP__ -DPOSIX -m64 -mxop
LDFLAGS_POSIXXOP  = $(LDFLAGS) -L$(LIBGMP_POSIXXOP)/lib -lm -lpthread -lgmp

posixXOP: hashcat-cliXOP.bin

rules-posixXOP: rules-debugXOP.bin

rules-debugXOP.bin: $(DIR_POSIXXOP)/rp.LINUX.XOP.o src/rules-debug.c
	$(CC_POSIXXOP) $(CFLAGS_POSIXXOP) $(DIR_POSIXXOP)/*.LINUX.XOP.o src/rules-debug.c -o rules-debugXOP.bin $(LDFLAGS_POSIXXOP)

hashcat-posixXOP: hashcat-cliXOP.bin

hashcat-cliXOP.bin: $(DIR_POSIXXOP)/tsearch.LINUX.XOP.o $(DIR_POSIXXOP)/rp.LINUX.XOP.o $(DIR_POSIXXOP)/engine.LINUX.XOP.o src/hashcat-cli.c
	$(CC_POSIXXOP) $(CFLAGS_POSIXXOP) $(DIR_POSIXXOP)/*.LINUX.XOP.o src/hashcat-cli.c -o hashcat-cliXOP.bin $(LDFLAGS_POSIXXOP)

engine-posixXOP: $(DIR_POSIXXOP)/engine.LINUX.XOP.o

$(DIR_POSIXXOP)/engine.LINUX.XOP.o: $(DIR_POSIXXOP)/common.LINUX.XOP.o src/engine.c
	$(CC_POSIXXOP) $(CFLAGS_POSIXXOP) -c src/engine.c -o $(DIR_POSIXXOP)/engine.LINUX.XOP.o

rp-posixXOP: $(DIR_POSIXXOP)/rp.LINUX.XOP.o

$(DIR_POSIXXOP)/rp.LINUX.XOP.o: $(DIR_POSIXXOP)/common.LINUX.XOP.o src/rp.c
	$(CC_POSIXXOP) $(CFLAGS_POSIXXOP) -c src/rp.c -o $(DIR_POSIXXOP)/rp.LINUX.XOP.o

tsearch-posixXOP: $(DIR_POSIXXOP)/tsearch.LINUX.XOP.o

$(DIR_POSIXXOP)/tsearch.LINUX.XOP.o: $(DIR_POSIXXOP)/common.LINUX.XOP.o src/tsearch.c
	$(CC_POSIXXOP) $(CFLAGS_POSIXXOP) -c src/tsearch.c -o $(DIR_POSIXXOP)/tsearch.LINUX.XOP.o

common-posixXOP: $(DIR_POSIXXOP)/common.LINUX.XOP.o

$(DIR_POSIXXOP)/common.LINUX.XOP.o: src/common.c
	$(CC_POSIXXOP) $(CFLAGS_POSIXXOP) -c src/common.c -o $(DIR_POSIXXOP)/common.LINUX.XOP.o

##
## WINDOWS32
##

DIR_WINDOWS32     = obj
LIBGMP_WINDOW32   = /opt/hashcat-deps/gmp/win32
CC_WINDOWS32      = i686-w64-mingw32-gcc
CFLAGS_WINDOWS32  = $(CFLAGS) -I$(LIBGMP_WINDOW32)/include -D__HC_x86_32__ -DWINDOWS -m32 -msse2 -D__USE_MINGW_ANSI_STDIO=1 -mstackrealign
LDFLAGS_WINDOWS32 = $(LDFLAGS) -L$(LIBGMP_WINDOW32)/lib -lm -lgmp

windows32: hashcat-cli32.exe

rules-windows32: rules-debug32.exe

rules-debug32.exe: $(DIR_WINDOWS32)/rp.WIN.32.o src/rules-debug.c
	$(CC_WINDOWS32) $(CFLAGS_WINDOWS32) $(DIR_WINDOWS32)/*.WIN.32.o src/rules-debug.c -o rules-debug32.exe $(LDFLAGS_WINDOWS32)

hashcat-windows32: hashcat-cli32.exe

hashcat-cli32.exe: $(DIR_WINDOWS32)/tsearch.WIN.32.o $(DIR_WINDOWS32)/rp.WIN.32.o $(DIR_WINDOWS32)/engine.WIN.32.o src/hashcat-cli.c
	$(CC_WINDOWS32) $(CFLAGS_WINDOWS32) $(DIR_WINDOWS32)/*.WIN.32.o /usr/i686-w64-mingw32/lib/CRT_glob.o src/hashcat-cli.c -o hashcat-cli32.exe $(LDFLAGS_WINDOWS32)

engine-windows32: $(DIR_WINDOWS32)/engine.WIN.32.o

$(DIR_WINDOWS32)/engine.WIN.32.o: $(DIR_WINDOWS32)/common.WIN.32.o src/engine.c
	$(CC_WINDOWS32) $(CFLAGS_WINDOWS32) -c src/engine.c -o $(DIR_WINDOWS32)/engine.WIN.32.o

rp-windows32: $(DIR_WINDOWS32)/rp.WIN.32.o

$(DIR_WINDOWS32)/rp.WIN.32.o: $(DIR_WINDOWS32)/common.WIN.32.o src/rp.c
	$(CC_WINDOWS32) $(CFLAGS_WINDOWS32) -c src/rp.c -o $(DIR_WINDOWS32)/rp.WIN.32.o

tsearch-windows32: $(DIR_WINDOWS32)/tsearch.WIN.32.o

$(DIR_WINDOWS32)/tsearch.WIN.32.o: $(DIR_WINDOWS32)/common.WIN.32.o src/tsearch.c
	$(CC_WINDOWS32) $(CFLAGS_WINDOWS32) -c src/tsearch.c -o $(DIR_WINDOWS32)/tsearch.WIN.32.o

common-windows32: $(DIR_WINDOWS32)/common.WIN.32.o

$(DIR_WINDOWS32)/common.WIN.32.o: src/common.c
	$(CC_WINDOWS32) $(CFLAGS_WINDOWS32) -c src/common.c -o $(DIR_WINDOWS32)/common.WIN.32.o

##
## WINDOWS64
##

DIR_WINDOWS64     = obj
LIBGMP_WINDOWS64  = /opt/hashcat-deps/gmp/win64
CC_WINDOWS64      = x86_64-w64-mingw32-gcc
CFLAGS_WINDOWS64  = $(CFLAGS) -I$(LIBGMP_WINDOWS64)/include -D__HC_x86_64__ -DWINDOWS -m64 -msse2 -D__USE_MINGW_ANSI_STDIO=1 -mstackrealign
LDFLAGS_WINDOWS64 = $(LDFLAGS) -L$(LIBGMP_WINDOWS64)/lib -lm -lgmp

windows64: hashcat-cli64.exe

rules-windows64: rules-debug64.exe

rules-debug64.exe: $(DIR_WINDOWS64)/rp.WIN.64.o src/rules-debug.c
	$(CC_WINDOWS64) $(CFLAGS_WINDOWS64) $(DIR_WINDOWS64)/*.WIN.64.o src/rules-debug.c -o rules-debug64.exe $(LDFLAGS_WINDOWS64)

hashcat-windows64: hashcat-cli64.exe

hashcat-cli64.exe: $(DIR_WINDOWS64)/tsearch.WIN.64.o $(DIR_WINDOWS64)/rp.WIN.64.o $(DIR_WINDOWS64)/engine.WIN.64.o src/hashcat-cli.c
	$(CC_WINDOWS64) $(CFLAGS_WINDOWS64) $(DIR_WINDOWS64)/*.WIN.64.o /usr/x86_64-w64-mingw32/lib/CRT_glob.o src/hashcat-cli.c -o hashcat-cli64.exe $(LDFLAGS_WINDOWS64)

engine-windows64: $(DIR_WINDOWS64)/engine.WIN.64.o

$(DIR_WINDOWS64)/engine.WIN.64.o: $(DIR_WINDOWS64)/common.WIN.64.o src/engine.c
	$(CC_WINDOWS64) $(CFLAGS_WINDOWS64) -c src/engine.c -o $(DIR_WINDOWS64)/engine.WIN.64.o

rp-windows64: $(DIR_WINDOWS64)/rp.WIN.64.o

$(DIR_WINDOWS64)/rp.WIN.64.o: $(DIR_WINDOWS64)/common.WIN.64.o src/rp.c
	$(CC_WINDOWS64) $(CFLAGS_WINDOWS64) -c src/rp.c -o $(DIR_WINDOWS64)/rp.WIN.64.o

tsearch-windows64: $(DIR_WINDOWS64)/tsearch.WIN.64.o

$(DIR_WINDOWS64)/tsearch.WIN.64.o: $(DIR_WINDOWS64)/common.WIN.64.o src/tsearch.c
	$(CC_WINDOWS64) $(CFLAGS_WINDOWS64) -c src/tsearch.c -o $(DIR_WINDOWS64)/tsearch.WIN.64.o

common-windows64: $(DIR_WINDOWS64)/common.WIN.64.o

$(DIR_WINDOWS64)/common.WIN.64.o: src/common.c
	$(CC_WINDOWS64) $(CFLAGS_WINDOWS64) -c src/common.c -o $(DIR_WINDOWS64)/common.WIN.64.o

##
## WINDOWSAVX
##

DIR_WINDOWSAVX     = obj
LIBGMP_WINDOWSAVX  = /opt/hashcat-deps/gmp/win64
CC_WINDOWSAVX      = x86_64-w64-mingw32-gcc
CFLAGS_WINDOWSAVX  = $(CFLAGS) -I$(LIBGMP_WINDOWSAVX)/include -D__HC_AVX__ -DWINDOWS -m64 -mavx -D__USE_MINGW_ANSI_STDIO=1 -mstackrealign
LDFLAGS_WINDOWSAVX = $(LDFLAGS) -L$(LIBGMP_WINDOWSAVX)/lib -lm -lgmp

windowsAVX: hashcat-cliAVX.exe

rules-windowsAVX: rules-debugAVX.exe

rules-debugAVX.exe: $(DIR_WINDOWSAVX)/rp.WIN.AVX.o src/rules-debug.c
	$(CC_WINDOWSAVX) $(CFLAGS_WINDOWSAVX) $(DIR_WINDOWSAVX)/*.WIN.AVX.o src/rules-debug.c -o rules-debugAVX.exe $(LDFLAGS_WINDOWSAVX)

hashcat-windowsAVX: hashcat-cliAVX.exe

hashcat-cliAVX.exe: $(DIR_WINDOWSAVX)/tsearch.WIN.AVX.o $(DIR_WINDOWSAVX)/rp.WIN.AVX.o $(DIR_WINDOWSAVX)/engine.WIN.AVX.o src/hashcat-cli.c
	$(CC_WINDOWSAVX) $(CFLAGS_WINDOWSAVX) $(DIR_WINDOWSAVX)/*.WIN.AVX.o /usr/x86_64-w64-mingw32/lib/CRT_glob.o src/hashcat-cli.c -o hashcat-cliAVX.exe $(LDFLAGS_WINDOWSAVX)

engine-windowsAVX: $(DIR_WINDOWSAVX)/engine.WIN.AVX.o

$(DIR_WINDOWSAVX)/engine.WIN.AVX.o: $(DIR_WINDOWSAVX)/common.WIN.AVX.o src/engine.c
	$(CC_WINDOWSAVX) $(CFLAGS_WINDOWSAVX) -c src/engine.c -o $(DIR_WINDOWSAVX)/engine.WIN.AVX.o

rp-windowsAVX: $(DIR_WINDOWSAVX)/rp.WIN.AVX.o

$(DIR_WINDOWSAVX)/rp.WIN.AVX.o: $(DIR_WINDOWSAVX)/common.WIN.AVX.o src/rp.c
	$(CC_WINDOWSAVX) $(CFLAGS_WINDOWSAVX) -c src/rp.c -o $(DIR_WINDOWSAVX)/rp.WIN.AVX.o

tsearch-windowsAVX: $(DIR_WINDOWSAVX)/tsearch.WIN.AVX.o

$(DIR_WINDOWSAVX)/tsearch.WIN.AVX.o: $(DIR_WINDOWSAVX)/common.WIN.AVX.o src/tsearch.c
	$(CC_WINDOWSAVX) $(CFLAGS_WINDOWSAVX) -c src/tsearch.c -o $(DIR_WINDOWSAVX)/tsearch.WIN.AVX.o

common-windowsAVX: $(DIR_WINDOWSAVX)/common.WIN.AVX.o

$(DIR_WINDOWSAVX)/common.WIN.AVX.o: src/common.c
	$(CC_WINDOWSAVX) $(CFLAGS_WINDOWSAVX) -c src/common.c -o $(DIR_WINDOWSAVX)/common.WIN.AVX.o

##
## WINDOWSAVX2
##

DIR_WINDOWSAVX2     = obj
LIBGMP_WINDOWSAVX2  = /opt/hashcat-deps/gmp/win64
CC_WINDOWSAVX2      = x86_64-w64-mingw32-gcc
CFLAGS_WINDOWSAVX2  = $(CFLAGS) -I$(LIBGMP_WINDOWSAVX2)/include -D__HC_AVX2__ -DWINDOWS -m64 -mavx2 -D__USE_MINGW_ANSI_STDIO=1 -mstackrealign
LDFLAGS_WINDOWSAVX2 = $(LDFLAGS) -L$(LIBGMP_WINDOWSAVX2)/lib -lm -lgmp

windowsAVX2: hashcat-cliAVX2.exe

rules-windowsAVX2: rules-debugAVX2.exe

rules-debugAVX2.exe: $(DIR_WINDOWSAVX2)/rp.WIN.AVX2.o src/rules-debug.c
	$(CC_WINDOWSAVX2) $(CFLAGS_WINDOWSAVX2) $(DIR_WINDOWSAVX2)/*.WIN.AVX2.o src/rules-debug.c -o rules-debugAVX2.exe $(LDFLAGS_WINDOWSAVX2)

hashcat-windowsAVX2: hashcat-cliAVX2.exe

hashcat-cliAVX2.exe: $(DIR_WINDOWSAVX2)/tsearch.WIN.AVX2.o $(DIR_WINDOWSAVX2)/rp.WIN.AVX2.o $(DIR_WINDOWSAVX2)/engine.WIN.AVX2.o src/hashcat-cli.c
	$(CC_WINDOWSAVX2) $(CFLAGS_WINDOWSAVX2) $(DIR_WINDOWSAVX2)/*.WIN.AVX2.o /usr/x86_64-w64-mingw32/lib/CRT_glob.o src/hashcat-cli.c -o hashcat-cliAVX2.exe $(LDFLAGS_WINDOWSAVX2)

engine-windowsAVX2: $(DIR_WINDOWSAVX2)/engine.WIN.AVX2.o

$(DIR_WINDOWSAVX2)/engine.WIN.AVX2.o: $(DIR_WINDOWSAVX2)/common.WIN.AVX2.o src/engine.c
	$(CC_WINDOWSAVX2) $(CFLAGS_WINDOWSAVX2) -c src/engine.c -o $(DIR_WINDOWSAVX2)/engine.WIN.AVX2.o

rp-windowsAVX2: $(DIR_WINDOWSAVX2)/rp.WIN.AVX2.o

$(DIR_WINDOWSAVX2)/rp.WIN.AVX2.o: $(DIR_WINDOWSAVX2)/common.WIN.AVX2.o src/rp.c
	$(CC_WINDOWSAVX2) $(CFLAGS_WINDOWSAVX2) -c src/rp.c -o $(DIR_WINDOWSAVX2)/rp.WIN.AVX2.o

tsearch-windowsAVX2: $(DIR_WINDOWSAVX2)/tsearch.WIN.AVX2.o

$(DIR_WINDOWSAVX2)/tsearch.WIN.AVX2.o: $(DIR_WINDOWSAVX2)/common.WIN.AVX2.o src/tsearch.c
	$(CC_WINDOWSAVX2) $(CFLAGS_WINDOWSAVX2) -c src/tsearch.c -o $(DIR_WINDOWSAVX2)/tsearch.WIN.AVX2.o

common-windowsAVX2: $(DIR_WINDOWSAVX2)/common.WIN.AVX2.o

$(DIR_WINDOWSAVX2)/common.WIN.AVX2.o: src/common.c
	$(CC_WINDOWSAVX2) $(CFLAGS_WINDOWSAVX2) -c src/common.c -o $(DIR_WINDOWSAVX2)/common.WIN.AVX2.o

##
## WINDOWSXOP
##

DIR_WINDOWSXOP     = obj
LIBGMP_WINDOWSXOP  = /opt/hashcat-deps/gmp/win64
CC_WINDOWSXOP      = x86_64-w64-mingw32-gcc
CFLAGS_WINDOWSXOP  = $(CFLAGS) -I$(LIBGMP_WINDOWSXOP)/include -D__HC_XOP__ -DWINDOWS -m64 -mxop -D__USE_MINGW_ANSI_STDIO=1 -mstackrealign
LDFLAGS_WINDOWSXOP = $(LDFLAGS) -L$(LIBGMP_WINDOWSXOP)/lib -lm -lgmp

windowsXOP: hashcat-cliXOP.exe

rules-windowsXOP: rules-debugXOP.exe

rules-debugXOP.exe: $(DIR_WINDOWSXOP)/rp.WIN.XOP.o src/rules-debug.c
	$(CC_WINDOWSXOP) $(CFLAGS_WINDOWSXOP) $(DIR_WINDOWSXOP)/*.WIN.XOP.o src/rules-debug.c -o rules-debugXOP.exe $(LDFLAGS_WINDOWSXOP)

hashcat-windowsXOP: hashcat-cliXOP.exe

hashcat-cliXOP.exe: $(DIR_WINDOWSXOP)/tsearch.WIN.XOP.o $(DIR_WINDOWSXOP)/rp.WIN.XOP.o $(DIR_WINDOWSXOP)/engine.WIN.XOP.o src/hashcat-cli.c
	$(CC_WINDOWSXOP) $(CFLAGS_WINDOWSXOP) $(DIR_WINDOWSXOP)/*.WIN.XOP.o /usr/x86_64-w64-mingw32/lib/CRT_glob.o src/hashcat-cli.c -o hashcat-cliXOP.exe $(LDFLAGS_WINDOWSXOP)

engine-windowsXOP: $(DIR_WINDOWSXOP)/engine.WIN.XOP.o

$(DIR_WINDOWSXOP)/engine.WIN.XOP.o: $(DIR_WINDOWSXOP)/common.WIN.XOP.o src/engine.c
	$(CC_WINDOWSXOP) $(CFLAGS_WINDOWSXOP) -c src/engine.c -o $(DIR_WINDOWSXOP)/engine.WIN.XOP.o

rp-windowsXOP: $(DIR_WINDOWSXOP)/rp.WIN.XOP.o

$(DIR_WINDOWSXOP)/rp.WIN.XOP.o: $(DIR_WINDOWSXOP)/common.WIN.XOP.o src/rp.c
	$(CC_WINDOWSXOP) $(CFLAGS_WINDOWSXOP) -c src/rp.c -o $(DIR_WINDOWSXOP)/rp.WIN.XOP.o

tsearch-windowsXOP: $(DIR_WINDOWSXOP)/tsearch.WIN.XOP.o

$(DIR_WINDOWSXOP)/tsearch.WIN.XOP.o: $(DIR_WINDOWSXOP)/common.WIN.XOP.o src/tsearch.c
	$(CC_WINDOWSXOP) $(CFLAGS_WINDOWSXOP) -c src/tsearch.c -o $(DIR_WINDOWSXOP)/tsearch.WIN.XOP.o

common-windowsXOP: $(DIR_WINDOWSXOP)/common.WIN.XOP.o

$(DIR_WINDOWSXOP)/common.WIN.XOP.o: src/common.c
	$(CC_WINDOWSXOP) $(CFLAGS_WINDOWSXOP) -c src/common.c -o $(DIR_WINDOWSXOP)/common.WIN.XOP.o
