##
## Author......: Jens Steube <jens.steube@gmail.com>
## License.....: MIT
##

all: binaries

##
## Detect host OS
##

OS       := $(shell uname)

##
## Makefile flags
##

MAKEFLAGS += -l -j -rR --no-print-directory

ifneq ($(findstring clean,$(MAKECMDGOALS)),)
MAKEFLAGS += -j 1
endif

# -mstackrealign is required otherwise crashes on windows xp, see hashcat v0.41 and v0.42

CFLAGS  := -W -Wall -pipe -I include/ -O2 -s -fomit-frame-pointer -funroll-loops
#CFLAGS  := -W -Wall -pipe -I include/ -g
LDFLAGS :=

##
## OSX64
##

DIR_OSX64      = obj/osx64
CC_OSX64       = i686-apple-darwin10-gcc
LIBGMP_OSX64   = deps/gmp/osx64
CFLAGS_OSX64   = $(CFLAGS) -I$(LIBGMP_OSX64)/include -D__HC_x86_64__ -DOSX -m64 -msse2 -arch x86_64 -mmacosx-version-min=10.5
LDFLAGS_OSX64  = $(LDFLAGS) -L$(LIBGMP_OSX64)/lib -lm -lpthread -lgmp

$(DIR_OSX64)/rules-debug64.app: $(DIR_OSX64)/rp.o src/rules-debug.c
	$(CC_OSX64) $(filter-out -s,$(CFLAGS_OSX64)) $(DIR_OSX64)/*.o src/rules-debug.c -o $@ $(LDFLAGS_OSX64)
	cp $@ .

$(DIR_OSX64)/hashcat-cli64.app: $(DIR_OSX64)/tsearch.o $(DIR_OSX64)/rp.o $(DIR_OSX64)/engine.o src/hashcat-cli.c
	$(CC_OSX64) $(filter-out -s,$(CFLAGS_OSX64)) $(DIR_OSX64)/*.o src/hashcat-cli.c -o $@ $(LDFLAGS_OSX64)
	cp $@ .

$(DIR_OSX64)/engine.o: $(DIR_OSX64)/common.o src/engine.c
	$(CC_OSX64) $(CFLAGS_OSX64) -c src/engine.c -o $@

$(DIR_OSX64)/rp.o: $(DIR_OSX64)/common.o src/rp.c
	$(CC_OSX64) $(CFLAGS_OSX64) -c src/rp.c -o $@

$(DIR_OSX64)/tsearch.o: $(DIR_OSX64)/common.o src/tsearch.c
	$(CC_OSX64) $(CFLAGS_OSX64) -c src/tsearch.c -o $@

$(DIR_OSX64)/common.o: src/common.c
	$(CC_OSX64) $(CFLAGS_OSX64) -c src/common.c -o $@

##
## FREEBSD32
##

DIR_FREEBSD32      = obj/freebsd32
CC_FREEBSD32       = gcc
CFLAGS_FREEBSD32   = $(CFLAGS) -I/usr/local/include -DFREEBSD -m32 -msse2
LDFLAGS_FREEBSD32  = $(LDFLAGS) -L/usr/local/lib -lgmp -lm -lpthread -lc

$(DIR_FREEBSD32)/rules-debug32.bin: $(DIR_FREEBSD32)/rp.o src/rules-debug.c
	$(CC_FREEBSD32) $(CFLAGS_FREEBSD32) $(DIR_FREEBSD32)/*.o src/rules-debug.c -o $@ $(LDFLAGS_FREEBSD32)
	cp $@ .

$(DIR_FREEBSD32)/hashcat-cli32.bin: $(DIR_FREEBSD32)/tsearch.o $(DIR_FREEBSD32)/rp.o $(DIR_FREEBSD32)/engine.o src/hashcat-cli.c
	$(CC_FREEBSD32) $(CFLAGS_FREEBSD32) $(DIR_FREEBSD32)/*.o src/hashcat-cli.c -o $@ $(LDFLAGS_FREEBSD32)
	cp $@ .

$(DIR_FREEBSD32)/engine.o: $(DIR_FREEBSD32)/common.o src/engine.c
	$(CC_FREEBSD32) $(CFLAGS_FREEBSD32) -c src/engine.c -o $@

$(DIR_FREEBSD32)/rp.o: $(DIR_FREEBSD32)/common.o src/rp.c
	$(CC_FREEBSD32) $(CFLAGS_FREEBSD32) -c src/rp.c -o $@

$(DIR_FREEBSD32)/tsearch.o: $(DIR_FREEBSD32)/common.o src/tsearch.c
	$(CC_FREEBSD32) $(CFLAGS_FREEBSD32) -c src/tsearch.c -o $@

$(DIR_FREEBSD32)/common.o: src/common.c
	$(CC_FREEBSD32) $(CFLAGS_FREEBSD32) -c src/common.c -o $@

##
## FREEBSD64
##

DIR_FREEBSD64      = obj/freebsd64
CC_FREEBSD64       = gcc
CFLAGS_FREEBSD64   = $(CFLAGS) -I/usr/local/include -DFREEBSD -m64 -msse2
LDFLAGS_FREEBSD64  = $(LDFLAGS) -L/usr/local/lib -lgmp -lm -lpthread -lc

$(DIR_FREEBSD64)/rules-debug64.bin: $(DIR_FREEBSD64)/rp.o src/rules-debug.c
	$(CC_FREEBSD64) $(CFLAGS_FREEBSD64) $(DIR_FREEBSD64)/*.o src/rules-debug.c -o $@ $(LDFLAGS_FREEBSD64)
	cp $@ .

$(DIR_FREEBSD64)/hashcat-cli64.bin: $(DIR_FREEBSD64)/tsearch.o $(DIR_FREEBSD64)/rp.o $(DIR_FREEBSD64)/engine.o src/hashcat-cli.c
	$(CC_FREEBSD64) $(CFLAGS_FREEBSD64) $(DIR_FREEBSD64)/*.o src/hashcat-cli.c -o $@ $(LDFLAGS_FREEBSD64)
	cp $@ .

$(DIR_FREEBSD64)/engine.o: $(DIR_FREEBSD64)/common.o src/engine.c
	$(CC_FREEBSD64) $(CFLAGS_FREEBSD64) -c src/engine.c -o $@

$(DIR_FREEBSD64)/rp.o: $(DIR_FREEBSD64)/common.o src/rp.c
	$(CC_FREEBSD64) $(CFLAGS_FREEBSD64) -c src/rp.c -o $@

$(DIR_FREEBSD64)/tsearch.o: $(DIR_FREEBSD64)/common.o src/tsearch.c
	$(CC_FREEBSD64) $(CFLAGS_FREEBSD64) -c src/tsearch.c -o $@

$(DIR_FREEBSD64)/common.o: src/common.c
	$(CC_FREEBSD64) $(CFLAGS_FREEBSD64) -c src/common.c -o $@

##
## FREEBSDXOP
##

DIR_FREEBSDXOP      = obj/freebsdXOP
CC_FREEBSDXOP       = gcc
CFLAGS_FREEBSDXOP   = $(CFLAGS) -I/usr/local/include -DFREEBSD -mxop
LDFLAGS_FREEBSDXOP  = $(LDFLAGS) -L/usr/local/lib -lgmp -lm -lpthread -lc

$(DIR_FREEBSDXOP)/rules-debugXOP.bin: $(DIR_FREEBSDXOP)/rp.o src/rules-debug.c
	$(CC_FREEBSDXOP) $(CFLAGS_FREEBSDXOP) $(DIR_FREEBSDXOP)/*.o src/rules-debug.c -o $@ $(LDFLAGS_FREEBSDXOP)
	cp $@ .

$(DIR_FREEBSDXOP)/hashcat-cliXOP.bin: $(DIR_FREEBSDXOP)/tsearch.o $(DIR_FREEBSDXOP)/rp.o $(DIR_FREEBSDXOP)/engine.o src/hashcat-cli.c
	$(CC_FREEBSDXOP) $(CFLAGS_FREEBSDXOP) $(DIR_FREEBSDXOP)/*.o src/hashcat-cli.c -o $@ $(LDFLAGS_FREEBSDXOP)
	cp $@ .

$(DIR_FREEBSDXOP)/engine.o: $(DIR_FREEBSDXOP)/common.o src/engine.c
	$(CC_FREEBSDXOP) $(CFLAGS_FREEBSDXOP) -c src/engine.c -o $@

$(DIR_FREEBSDXOP)/rp.o: $(DIR_FREEBSDXOP)/common.o src/rp.c
	$(CC_FREEBSDXOP) $(CFLAGS_FREEBSDXOP) -c src/rp.c -o $@

$(DIR_FREEBSDXOP)/tsearch.o: $(DIR_FREEBSDXOP)/common.o src/tsearch.c
	$(CC_FREEBSDXOP) $(CFLAGS_FREEBSDXOP) -c src/tsearch.c -o $@

$(DIR_FREEBSDXOP)/common.o: src/common.c
	$(CC_FREEBSDXOP) $(CFLAGS_FREEBSDXOP) -c src/common.c -o $@

##
## LINUX32
##

DIR_LINUX32      = obj/linux32
LIBGMP_LINUX32   = deps/gmp/linux32
CC_LINUX32       = gcc
CFLAGS_LINUX32   = $(CFLAGS) -I$(LIBGMP_LINUX32)/include -D__HC_x86_32__ -DLINUX -m32 -msse2
LDFLAGS_LINUX32  = $(LDFLAGS) -L$(LIBGMP_LINUX32)/lib -lm -lpthread -lgmp

$(DIR_LINUX32)/rules-debug32.bin: $(DIR_LINUX32)/rp.o src/rules-debug.c
	$(CC_LINUX32) $(CFLAGS_LINUX32) $(DIR_LINUX32)/*.o src/rules-debug.c -o $@ $(LDFLAGS_LINUX32)
	cp $@ .

$(DIR_LINUX32)/hashcat-cli32.bin: $(DIR_LINUX32)/tsearch.o $(DIR_LINUX32)/rp.o  $(DIR_LINUX32)/engine.o src/hashcat-cli.c
	$(CC_LINUX32) $(CFLAGS_LINUX32) $(DIR_LINUX32)/*.o src/hashcat-cli.c -o $@ $(LDFLAGS_LINUX32)
	cp $@ .

$(DIR_LINUX32)/engine.o: $(DIR_LINUX32)/common.o src/engine.c
	$(CC_LINUX32) $(CFLAGS_LINUX32) -c src/engine.c -o $@

$(DIR_LINUX32)/rp.o: $(DIR_LINUX32)/common.o src/rp.c
	$(CC_LINUX32) $(CFLAGS_LINUX32) -c src/rp.c -o $@

$(DIR_LINUX32)/tsearch.o: $(DIR_LINUX32)/common.o src/tsearch.c
	$(CC_LINUX32) $(CFLAGS_LINUX32) -c src/tsearch.c -o $@

$(DIR_LINUX32)/common.o: src/common.c
	$(CC_LINUX32) $(CFLAGS_LINUX32) -c src/common.c -o $@

##
## LINUX64
##

DIR_LINUX64      = obj/linux64
LIBGMP_LINUX64   = deps/gmp/linux64
CC_LINUX64       = gcc
CFLAGS_LINUX64   = $(CFLAGS) -I$(LIBGMP_LINUX64)/include -D__HC_x86_64__ -DLINUX -m64 -msse2
LDFLAGS_LINUX64  = $(LDFLAGS) -L$(LIBGMP_LINUX64)/lib -lm -lpthread -lgmp

$(DIR_LINUX64)/rules-debug64.bin: $(DIR_LINUX64)/rp.o src/rules-debug.c
	$(CC_LINUX64) $(CFLAGS_LINUX64) $(DIR_LINUX64)/*.o src/rules-debug.c -o $@ $(LDFLAGS_LINUX64)
	cp $@ .

$(DIR_LINUX64)/hashcat-cli64.bin: $(DIR_LINUX64)/tsearch.o $(DIR_LINUX64)/rp.o $(DIR_LINUX64)/engine.o src/hashcat-cli.c
	$(CC_LINUX64) $(CFLAGS_LINUX64) $(DIR_LINUX64)/*.o src/hashcat-cli.c -o $@ $(LDFLAGS_LINUX64)
	cp $@ .

$(DIR_LINUX64)/engine.o: $(DIR_LINUX64)/common.o src/engine.c
	$(CC_LINUX64) $(CFLAGS_LINUX64) -c src/engine.c -o $@

$(DIR_LINUX64)/rp.o: $(DIR_LINUX64)/common.o src/rp.c
	$(CC_LINUX64) $(CFLAGS_LINUX64) -c src/rp.c -o $@

$(DIR_LINUX64)/tsearch.o: $(DIR_LINUX64)/common.o src/tsearch.c
	$(CC_LINUX64) $(CFLAGS_LINUX64) -c src/tsearch.c -o $@

$(DIR_LINUX64)/common.o: src/common.c
	$(CC_LINUX64) $(CFLAGS_LINUX64) -c src/common.c -o $@

##
## LINUXXOP
##

DIR_LINUXXOP      = obj/linuxXOP
LIBGMP_LINUXXOP   = deps/gmp/linux64
CC_LINUXXOP       = gcc
CFLAGS_LINUXXOP   = $(CFLAGS) -I$(LIBGMP_LINUXXOP)/include -D__HC_XOP__ -DLINUX -m64 -mxop
LDFLAGS_LINUXXOP  = $(LDFLAGS) -L$(LIBGMP_LINUXXOP)/lib -lm -lpthread -lgmp

$(DIR_LINUXXOP)/rules-debugXOP.bin: $(DIR_LINUXXOP)/rp.o src/rules-debug.c
	$(CC_LINUXXOP) $(CFLAGS_LINUXXOP) $(DIR_LINUXXOP)/*.o src/rules-debug.c -o $@ $(LDFLAGS_LINUXXOP)
	cp $@ .

$(DIR_LINUXXOP)/hashcat-cliXOP.bin: $(DIR_LINUXXOP)/tsearch.o $(DIR_LINUXXOP)/rp.o $(DIR_LINUXXOP)/engine.o src/hashcat-cli.c
	$(CC_LINUXXOP) $(CFLAGS_LINUXXOP) $(DIR_LINUXXOP)/*.o src/hashcat-cli.c -o $@ $(LDFLAGS_LINUXXOP)
	cp $@ .

$(DIR_LINUXXOP)/engine.o: $(DIR_LINUXXOP)/common.o src/engine.c
	$(CC_LINUXXOP) $(CFLAGS_LINUXXOP) -c src/engine.c -o $@

$(DIR_LINUXXOP)/rp.o: $(DIR_LINUXXOP)/common.o src/rp.c
	$(CC_LINUXXOP) $(CFLAGS_LINUXXOP) -c src/rp.c -o $@

$(DIR_LINUXXOP)/tsearch.o: $(DIR_LINUXXOP)/common.o src/tsearch.c
	$(CC_LINUXXOP) $(CFLAGS_LINUXXOP) -c src/tsearch.c -o $@

$(DIR_LINUXXOP)/common.o: src/common.c
	$(CC_LINUXXOP) $(CFLAGS_LINUXXOP) -c src/common.c -o $@

##
## WINDOWS32
##

DIR_WINDOWS32     = obj/win32
LIBGMP_WINDOW32   = deps/gmp/win32
CC_WINDOWS32      = i686-w64-mingw32-gcc
CFLAGS_WINDOWS32  = $(CFLAGS) -I$(LIBGMP_WINDOW32)/include -D__HC_x86_32__ -DWINDOWS -m32 -msse2 -D__USE_MINGW_ANSI_STDIO=1 -mstackrealign
LDFLAGS_WINDOWS32 = $(LDFLAGS) -L$(LIBGMP_WINDOW32)/lib -lm -lgmp

$(DIR_WINDOWS32)/rules-debug32.exe: $(DIR_WINDOWS32)/rp.o src/rules-debug.c
	$(CC_WINDOWS32) $(CFLAGS_WINDOWS32) $(DIR_WINDOWS32)/*.o src/rules-debug.c -o $@ $(LDFLAGS_WINDOWS32)
	cp $@ .

$(DIR_WINDOWS32)/hashcat-cli32.exe: $(DIR_WINDOWS32)/tsearch.o $(DIR_WINDOWS32)/rp.o $(DIR_WINDOWS32)/engine.o src/hashcat-cli.c
	$(CC_WINDOWS32) $(CFLAGS_WINDOWS32) $(DIR_WINDOWS32)/*.o /usr/i686-w64-mingw32/lib/CRT_glob.o src/hashcat-cli.c -o $@ $(LDFLAGS_WINDOWS32)
	cp $@ .

$(DIR_WINDOWS32)/engine.o: $(DIR_WINDOWS32)/common.o src/engine.c
	$(CC_WINDOWS32) $(CFLAGS_WINDOWS32) -c src/engine.c -o $@

$(DIR_WINDOWS32)/rp.o: $(DIR_WINDOWS32)/common.o src/rp.c
	$(CC_WINDOWS32) $(CFLAGS_WINDOWS32) -c src/rp.c -o $@

$(DIR_WINDOWS32)/tsearch.o: $(DIR_WINDOWS32)/common.o src/tsearch.c
	$(CC_WINDOWS32) $(CFLAGS_WINDOWS32) -c src/tsearch.c -o $@

$(DIR_WINDOWS32)/common.o: src/common.c
	$(CC_WINDOWS32) $(CFLAGS_WINDOWS32) -c src/common.c -o $@

##
## WINDOWS64
##

DIR_WINDOWS64     = obj/win64
LIBGMP_WINDOWS64  = deps/gmp/win64
CC_WINDOWS64      = x86_64-w64-mingw32-gcc
CFLAGS_WINDOWS64  = $(CFLAGS) -I$(LIBGMP_WINDOWS64)/include -D__HC_x86_64__ -DWINDOWS -m64 -msse2 -D__USE_MINGW_ANSI_STDIO=1 -mstackrealign
LDFLAGS_WINDOWS64 = $(LDFLAGS) -L$(LIBGMP_WINDOWS64)/lib -lm -lgmp

$(DIR_WINDOWS64)/rules-debug64.exe: $(DIR_WINDOWS64)/rp.o src/rules-debug.c
	$(CC_WINDOWS64) $(CFLAGS_WINDOWS64) $(DIR_WINDOWS64)/*.o src/rules-debug.c -o $@ $(LDFLAGS_WINDOWS64)
	cp $@ .

$(DIR_WINDOWS64)/hashcat-cli64.exe: $(DIR_WINDOWS64)/tsearch.o $(DIR_WINDOWS64)/rp.o $(DIR_WINDOWS64)/engine.o src/hashcat-cli.c
	$(CC_WINDOWS64) $(CFLAGS_WINDOWS64) $(DIR_WINDOWS64)/*.o /usr/x86_64-w64-mingw32/lib/CRT_glob.o src/hashcat-cli.c -o $@ $(LDFLAGS_WINDOWS64)
	cp $@ .

$(DIR_WINDOWS64)/engine.o: $(DIR_WINDOWS64)/common.o src/engine.c
	$(CC_WINDOWS64) $(CFLAGS_WINDOWS64) -c src/engine.c -o $@

$(DIR_WINDOWS64)/rp.o: $(DIR_WINDOWS64)/common.o src/rp.c
	$(CC_WINDOWS64) $(CFLAGS_WINDOWS64) -c src/rp.c -o $@

$(DIR_WINDOWS64)/tsearch.o: $(DIR_WINDOWS64)/common.o src/tsearch.c
	$(CC_WINDOWS64) $(CFLAGS_WINDOWS64) -c src/tsearch.c -o $@

$(DIR_WINDOWS64)/common.o: src/common.c
	$(CC_WINDOWS64) $(CFLAGS_WINDOWS64) -c src/common.c -o $@

##
## WINDOWSXOP
##

DIR_WINDOWSXOP     = obj/winXOP
LIBGMP_WINDOWSXOP  = deps/gmp/win64
CC_WINDOWSXOP      = x86_64-w64-mingw32-gcc
CFLAGS_WINDOWSXOP  = $(CFLAGS) -I$(LIBGMP_WINDOWSXOP)/include -D__HC_XOP__ -DWINDOWS -m64 -mxop -D__USE_MINGW_ANSI_STDIO=1 -mstackrealign
LDFLAGS_WINDOWSXOP = $(LDFLAGS) -L$(LIBGMP_WINDOWSXOP)/lib -lm -lgmp

$(DIR_WINDOWSXOP)/rules-debugXOP.exe: $(DIR_WINDOWSXOP)/rp.o src/rules-debug.c
	$(CC_WINDOWSXOP) $(CFLAGS_WINDOWSXOP) $(DIR_WINDOWSXOP)/*.o src/rules-debug.c -o $@ $(LDFLAGS_WINDOWSXOP)
	cp $@ .

$(DIR_WINDOWSXOP)/hashcat-cliXOP.exe: $(DIR_WINDOWSXOP)/tsearch.o $(DIR_WINDOWSXOP)/rp.o $(DIR_WINDOWSXOP)/engine.o src/hashcat-cli.c
	$(CC_WINDOWSXOP) $(CFLAGS_WINDOWSXOP) $(DIR_WINDOWSXOP)/*.o /usr/x86_64-w64-mingw32/lib/CRT_glob.o src/hashcat-cli.c -o $@ $(LDFLAGS_WINDOWSXOP)
	cp $@ .

$(DIR_WINDOWSXOP)/engine.o: $(DIR_WINDOWSXOP)/common.o src/engine.c
	$(CC_WINDOWSXOP) $(CFLAGS_WINDOWSXOP) -c src/engine.c -o $@

$(DIR_WINDOWSXOP)/rp.o: $(DIR_WINDOWSXOP)/common.o src/rp.c
	$(CC_WINDOWSXOP) $(CFLAGS_WINDOWSXOP) -c src/rp.c -o $@

$(DIR_WINDOWSXOP)/tsearch.o: $(DIR_WINDOWSXOP)/common.o src/tsearch.c
	$(CC_WINDOWSXOP) $(CFLAGS_WINDOWSXOP) -c src/tsearch.c -o $@

$(DIR_WINDOWSXOP)/common.o: src/common.c
	$(CC_WINDOWSXOP) $(CFLAGS_WINDOWSXOP) -c src/common.c -o $@

##
## User 
##

clean:
	rm -f *.bin *.exe *.app
	rm -f $(DIR_OSX64)/*
	rm -f $(DIR_FREEBSD32)/*
	rm -f $(DIR_FREEBSD64)/*
	rm -f $(DIR_FREEBSDXOP)/*
	rm -f $(DIR_LINUX32)/*
	rm -f $(DIR_LINUX64)/*
	rm -f $(DIR_LINUXXOP)/*
	rm -f $(DIR_WINDOWS32)/*
	rm -f $(DIR_WINDOWS64)/*
	rm -f $(DIR_WINDOWSXOP)/*
	rm -f core out word hash hashcat.pot
	rm -rf release

binaries: linux windows osx

osx: osx64
linux: linux32 linux64 linuxXOP
windows: windows32 windows64 windowsXOP
freebsd: freebsd32 freebsd64 freebsdXOP

osx64:      $(DIR_OSX64)/hashcat-cli64.app
freebsd32:  $(DIR_FREEBSD32)/hashcat-cli32.bin
freebsd64:  $(DIR_FREEBSD64)/hashcat-cli64.bin
freebsdXOP: $(DIR_FREEBSDXOP)/hashcat-cliXOP.bin
linux32:    $(DIR_LINUX32)/hashcat-cli32.bin
linux64:    $(DIR_LINUX64)/hashcat-cli64.bin
linuxXOP:   $(DIR_LINUXXOP)/hashcat-cliXOP.bin
windows32:  $(DIR_WINDOWS32)/hashcat-cli32.exe
windows64:  $(DIR_WINDOWS64)/hashcat-cli64.exe
windowsXOP: $(DIR_WINDOWSXOP)/hashcat-cliXOP.exe

release: binaries
	rm -rf release
	mkdir release
	cp -a $(DIR_OSX64)/hashcat-cli64.app       release/
	cp -a $(DIR_LINUX32)/hashcat-cli32.bin     release/
	cp -a $(DIR_LINUX64)/hashcat-cli64.bin     release/
	cp -a $(DIR_LINUXXOP)/hashcat-cliXOP.bin   release/
	cp -a $(DIR_WINDOWS32)/hashcat-cli32.exe   release/
	cp -a $(DIR_WINDOWS64)/hashcat-cli64.exe   release/
	cp -a $(DIR_WINDOWSXOP)/hashcat-cliXOP.exe release/
	cp -a charsets docs rules tables salts examples release/
	find release -type f -exec chmod 600 {} \;
	find release -type d -exec chmod 700 {} \;
	chmod 700 release/*.bin
	chmod 700 release/*.app
	unix2dos release/salts/*
	unix2dos release/rules/*
	unix2dos release/tables/*
	unix2dos release/docs/*
	unix2dos release/examples/*
