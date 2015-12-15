## Hashcat build documentation

### Revision:
* 1.02

### Authors:
* Gabriele Gristina <<matrix@hashcat.net>>

### Dependencies
To compile **Hashcat** you need to cross compile the **gmp** library for Linux (32/64 bit), Windows (32/64 bit) and OSX (64 bit). (see below)

### Building Hashcat
First get a copy of **Hashcat** repository

```sh
$ git clone https://github.com/hashcat/hashcat.git
```

Install the dependencies

```sh
$ cd hashcat
$ sudo ./tools/deps.sh
```

Run make depending on your os

```bash
$ make [linux|osx|windows|freebsd]
```

Not specifying an argument will cross-compile binaries for Linux, Windows and OSX.

If you want to compile native FreeBSD binaries, you will need **gmp** installed (/usr/ports/math/gmp). This has been tested on FreeBSD 10.2. 

Enjoy your fresh **Hashcat** binaries ;)
