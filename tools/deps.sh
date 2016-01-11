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

if [ $# -gt 0 ]; then
  if [ "$1" == "clean" ]; then
    ## make a fresh "deps" workspace
    rm -rf tmp/gmp* gmp/{linux32,linux64,win32,win64,osx64} && \
    mkdir -p gmp/{linux32,linux64,win32,win64,osx64} tmp && \
    cd tmp

    if [ $? -ne 0 ]; then
      echo "! Cannot cleanup the deps workspace."
      exit 1
    fi
  fi
fi

## install osx cross stuff
mkdir -p apple-pkgs
cd apple-pkgs

dpkg -l | grep libssl0.9.8 | grep ^ii &>/dev/null
if [ $? -ne 0 ]; then
  if [ ! -f "libssl0.9.8_0.9.8o-4squeeze14_amd64.deb" ]; then
    wget -c http://http.us.debian.org/debian/pool/main/o/openssl/libssl0.9.8_0.9.8o-4squeeze14_amd64.deb
    if [ $? -ne 0 ]; then
      echo "! failed to download libssl0.9.8 debian package"
      exit 1
    fi
  fi

  sudo dpkg -i libssl0.9.8_0.9.8o-4squeeze14_amd64.deb
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

  sudo dpkg -i apple-uni-sdk-10.5_20110407-0.flosoft1_amd64.deb
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

  sudo dpkg -i apple-uni-sdk-10.6_20110407-0.flosoft1_amd64.deb
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

  sudo dpkg -i apple-x86-odcctools_758.159-0flosoft11_amd64.deb
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

  sudo dpkg -i apple-x86-gcc_4.2.1~5646.1flosoft2_amd64.deb
  if [ $? -ne 0 ]; then
    echo "! failed to install apple-x86-gcc"
    exit 1
  fi
fi

cd ..

## installing needed packages
sudo apt-get -y install ${DEPS}
if [ $? -ne 0 ]; then
  echo "! failed to install deps packages"
  exit 1
fi

cd tmp

if [ ! -f "${GMP_VER}.tar.lz" ]; then
  ## download gmp source code
  wget -c https://gmplib.org/download/gmp/${GMP_VER}.tar.lz
  if [ $? -ne 0 ]; then
    echo "! failed to download GMP source code"
    exit 1
  fi
fi

if [ ! -d "${GMP_VER}" ]; then
  ## extract gmp source sode
  tar xf ${GMP_VER}.tar.lz
  if [ $? -ne 0 ]; then
    echo "! failed to extract GMP source code"
    exit 1
  fi
fi

newDir=$(tar tvf ${GMP_VER}.tar.lz | head -n1 | awk '{print $6}' | sed -e 's/\///g')
if [ "${newDir}" != "${GMP_VER}" ]; then
  mv ${newDir} ${GMP_VER}
fi

OS_TARGET="linux32 linux64 win32 win64 osx64"

for os in ${OS_TARGET}; do

  ret=1
  osx=1234
  # cleanup workspace
  rm -rf ${GMP_VER}/build && \
  mkdir -p ${GMP_VER}/build
  cd ${GMP_VER}/build

  # handling supported os
  case $os in
    linux32)
      ../configure --host=i386-pc-linux-gnu --prefix=${deps_dir}/gmp/linux32 --disable-shared && make install
      ;;
    linux64)
      ../configure --host=x86_64-pc-linux-gnu --prefix=${deps_dir}/gmp/linux64 --disable-shared && make install
      ;;
    win32)
      ../configure --host=i686-w64-mingw32 --prefix=${deps_dir}/gmp/win32 --disable-shared && make install
      ;;
    win64)
      ../configure --host=x86_64-w64-mingw32 --prefix=${deps_dir}/gmp/win64 --disable-shared && make install
      ;;
    osx64)
      cp ../configure ../configure.legacy
      sed -i 's/\(i686.*\)$/\1\n\tabilist=64/' ../configure && \
      ABI=64 ../configure --host=i686-apple-darwin10 --prefix=${deps_dir}/gmp/osx64 --disable-shared --disable-assembly && \
      make install
      osx=$?
      ;;
    *)
      echo "! Not supported OS (${os})."
      exit 1
      ;;
  esac

  ret=$?
  if [ ${osx} != 1234 ]; then
    mv ../configure.legacy ../configure
    ret=${osx}
  fi

  cd ..

  if [ ${ret} -ne 0 ]; then
    echo "! failed to build $os gmp library."
    exit 1
  fi

  rm -rf build
  cd ..

done

echo
echo "> Successfully resolved all dependencies for hashcat."
