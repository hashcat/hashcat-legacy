#!/bin/bash
# Author: Gabriele Gristina <matrix@hashcat.net>
# Revision: 1.1

## global vars
DEPS="git lzip gcc-multilib make m4 mingw-w64"
GMP_VER="gmp-6.1.0"

## enter the deps directory
cur_directory=$(dirname ${0})
script_directory=$(cd ${cur_directory} && pwd -P)
deps_dir=${script_directory}/../deps

mkdir -p ${deps_dir} # but it should already exist (is part of the repository)
cd ${deps_dir}

## root check
if [ $(id -u) -ne 0 ]; then
  echo "! Must be root"
  exit 1
fi

## make a fresh "deps" directories
rm -rf tmp/gmp* gmp/{linux32,linux64,win32,win64,osx64} && \
mkdir -p gmp/{linux32,linux64,win32,win64,osx64} tmp && \
cd tmp

if [ $? -ne 0 ]; then
  echo "! Cannot create the deps directories."
  exit 1
fi

## install osx cross stuff
mkdir -p apple-pkgs
cd apple-pkgs

dpkg -l | grep libssl0.9.8 | grep ^ii &>/dev/null
if [ $? -ne 0 ]; then
  if [ ! -f "libssl0.9.8_0.9.8o-4squeeze14_amd64.deb" ]; then
    wget -c http://archive.debian.org/debian-security/pool/updates/main/o/openssl/libssl0.9.8_0.9.8o-4squeeze14_amd64.deb
    if [ $? -ne 0 ]; then
      echo "! failed to download libssl0.9.8 debian package"
      exit 1
    fi
  fi

  dpkg -i libssl0.9.8_0.9.8o-4squeeze14_amd64.deb
  if [ $? -ne 0 ]; then
    echo "! failed to install libssl0.9.8"
    exit 1
  fi
fi


dpkg -l | grep apple-uni-sdk-10.5 | grep ^ii &>/dev/null
if [ $? -ne 0 ]; then
  if [ ! -f "apple-uni-sdk-10.5_20110407-0.flosoft1_amd64.deb" ]; then
    wget -c https://launchpad.net/~flosoft/+archive/ubuntu/cross-apple/+files/apple-uni-sdk-10.5_20110407-0.flosoft1_amd64.deb
    if [ $? -ne 0 ]; then
      echo "! failed to download apple-uni-sdk-10.5 debian package"
      exit 1
    fi
  fi

  dpkg -i apple-uni-sdk-10.5_20110407-0.flosoft1_amd64.deb
  if [ $? -ne 0 ]; then
    echo "! failed to install apple-uni-sdk-10.5"
    exit 1
  fi
fi

dpkg -l | grep apple-uni-sdk-10.6 | grep ^ii &>/dev/null
if [ $? -ne 0 ]; then
  if [ ! -f "apple-uni-sdk-10.6_20110407-0.flosoft1_amd64.deb" ]; then
    wget -c https://launchpad.net/~flosoft/+archive/ubuntu/cross-apple/+files/apple-uni-sdk-10.6_20110407-0.flosoft1_amd64.deb
    if [ $? -ne 0 ]; then
      echo "! failed to download apple-uni-sdk-10.6 debian package"
      exit 1
    fi
  fi

  dpkg -i apple-uni-sdk-10.6_20110407-0.flosoft1_amd64.deb
  if [ $? -ne 0 ]; then
    echo "! failed to install apple-uni-sdk-10.6"
    exit 1
  fi
fi

dpkg -l | grep apple-x86-odcctools | grep ^ii &>/dev/null
if [ $? -ne 0 ]; then
  if [ ! -f "apple-x86-odcctools_758.159-0flosoft11_amd64.deb" ]; then
    wget -c https://launchpad.net/~flosoft/+archive/ubuntu/cross-apple/+files/apple-x86-odcctools_758.159-0flosoft11_amd64.deb
    if [ $? -ne 0 ]; then
      echo "! failed to download apple-x86-odcctools debian package"
      exit 1
    fi
  fi

  dpkg -i apple-x86-odcctools_758.159-0flosoft11_amd64.deb
  if [ $? -ne 0 ]; then
    echo "! failed to install apple-x86-odcctools"
    exit 1
  fi
fi

dpkg -l | grep apple-x86-gcc | grep ^ii &>/dev/null
if [ $? -ne 0 ]; then
  if [ ! -f "apple-x86-gcc_4.2.1~5646.1flosoft2_amd64.deb" ]; then
    wget -c https://launchpad.net/~flosoft/+archive/ubuntu/cross-apple/+files/apple-x86-gcc_4.2.1~5646.1flosoft2_amd64.deb
    if [ $? -ne 0 ]; then
      echo "! failed to download apple-x86-gcc debian package"
      exit 1
    fi
  fi

  dpkg -i apple-x86-gcc_4.2.1~5646.1flosoft2_amd64.deb
  if [ $? -ne 0 ]; then
    echo "! failed to install apple-x86-gcc"
    exit 1
  fi
fi

cd ..

## installing needed packages
apt-get -y install ${DEPS}
if [ $? -ne 0 ]; then
  echo "! failed to install deps packages"
  exit 1
fi

## download gmp source code
wget -c https://gmplib.org/download/gmp/${GMP_VER}.tar.lz
if [ $? -ne 0 ]; then
  echo "! failed to download GMP source code"
  exit 1
fi

tar xf ${GMP_VER}.tar.lz
if [ $? -ne 0 ]; then
  echo "! failed to extract GMP source code"
  exit 1
fi

newDir=$(tar tvf ${GMP_VER}.tar.lz | head -n1 | awk '{print $6}' | sed -e 's/\///g')
if [ "${newDir}" != "${GMP_VER}" ]; then
  mv ${newDir} ${GMP_VER}
fi

## build gmp lib for linux32
cp -af ${GMP_VER} ${GMP_VER}-linux32
cd ${GMP_VER}-linux32 && \
./configure --host=i386-pc-linux-gnu --prefix=${deps_dir}/gmp/linux32 --disable-shared && \
sudo make install && \
cd .. && \
rm -rf ${GMP_VER}-linux32

if [ $? -ne 0 ]; then
  echo "! failed to build linux32 gmp lib."
  exit 1
fi

## build gmp lib for linux64
cp -af ${GMP_VER} ${GMP_VER}-linux64
cd ${GMP_VER}-linux64 && \
./configure --host=x86_64-pc-linux-gnu --prefix=${deps_dir}/gmp/linux64 --disable-shared && \
sudo make install && \
cd .. && \
rm -rf ${GMP_VER}-linux64

if [ $? -ne 0 ]; then
  echo "! failed to build linux64 gmp lib."
  exit 1
fi

## build gmp lib for win32
cp -af ${GMP_VER} ${GMP_VER}-win32
cd ${GMP_VER}-win32 && \
./configure --host=i686-w64-mingw32 --prefix=${deps_dir}/gmp/win32 --disable-shared && \
sudo make install && \
cd .. && \
rm -rf ${GMP_VER}-win32

if [ $? -ne 0 ]; then
  echo "! failed to build win32 gmp lib."
  exit 1
fi

## build gmp lib for win64
cp -af ${GMP_VER} ${GMP_VER}-win64
cd ${GMP_VER}-win64 && \
./configure --host=x86_64-w64-mingw32 --prefix=${deps_dir}/gmp/win64 --disable-shared && \
sudo make install && \
cd .. && \
rm -rf ${GMP_VER}-win64

if [ $? -ne 0 ]; then
  echo "! failed to build win64 gmp lib."
  exit 1
fi

## build gmp lib for osx64
cp -af ${GMP_VER} ${GMP_VER}-osx64
cd ${GMP_VER}-osx64 && \
sed -i 's/\(i686.*\)$/\1\n\tabilist=64/' configure && \
ABI=64 ./configure --host=i686-apple-darwin10 --prefix=${deps_dir}/gmp/osx64 --disable-shared --disable-assembly && \
sudo make install && \
cd .. && \
rm -rf ${GMP_VER}-osx64

if [ $? -ne 0 ]; then
  echo "! failed to build osx64 gmp lib."
  exit 1
fi

echo
echo "> Successfully resolved all dependencies for hashcat."
