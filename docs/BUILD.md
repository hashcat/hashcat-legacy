## Hashcat build documentation

### Revision:
* 1.0

### Authors:
* Gabriele Gristina <<matrix@hashcat.net>>

### Dependencies
To compile **Hashcat** you need cross compile the **gmp** library for Linux (32/64 bit), Windows (32/64 bit) and OSX (64 bit). (see below)

### Building Hashcat
First get a copy of **Hashcat** repository

```sh
$ git clone https://github.com/hashcat/hashcat.git
```

Install the dependencies

```sh
$ cd hashcat
$ sh tools/deps.sh
```

Run make depending on your os

```bash
$ make [linux|osx|windows]
```

Not specifying an argument will build for all OSes.

Enjoy your fresh **Hashcat** binaries ;)
