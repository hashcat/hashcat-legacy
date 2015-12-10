## Hashcat build documentation

### Revision:
* 1.01

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
$ make [linux|osx|windows]
```

Not specifying an argument will build for all OSes except FreeBSD.

If you want FreeBSD binaries, you will need to run this on a native FreeBSD amd64 system
```sh
$ make freebsd
```

This has been tested on FreeBSD 10.2 and will produce **./hashcat-cli64.elf**. You will need **gmp** installed (/usr/ports/math/gmp).

Enjoy your fresh **Hashcat** binaries ;)
