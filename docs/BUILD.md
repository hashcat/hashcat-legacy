## Hashcat build documentation

### Revision:
* 1.03

### Authors:
* Gabriele Gristina <<matrix@hashcat.net>>

### Dependencies
To compile **Hashcat** you need to cross compile the **gmp** library for Linux (32/64 bit), Windows (32/64 bit) and OSX (64 bit). (see below)

### Building Hashcat (static Makefile)
First get a copy of **Hashcat** repository

```sh
$ git clone https://github.com/hashcat/hashcat.git
```

Install the dependencies (root permission needed)

```sh
$ cd hashcat
$ ./tools/deps.sh
```

Run make depending on your os

```sh
$ make -f Makefile.legacy [linux|osx|windows|freebsd]
```

Not specifying an argument will cross-compile binaries for Linux, Windows and OSX.

If you want to compile native FreeBSD binaries, you will need **gmp** library installed (/usr/ports/math/gmp). This has been tested on FreeBSD 10.2. 

### Building Hashcat (autotools)
After get a copy of **Hashcat** repository you can build native binaries with autotools in that way:

```sh
$ cd hashcat
$ ./autogen.sh && ./configure && sudo make install
```

Enjoy your fresh **Hashcat** binaries ;)
