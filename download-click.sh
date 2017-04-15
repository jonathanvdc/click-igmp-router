#!/usr/bin/env bash

# Download click-2.0.1.
wget http://www.read.cs.ucla.edu/click/click-2.0.1.tar.gz
# Unzip the click tar.
tar xzf click-2.0.1.tar.gz
# Build click.
pushd click-2.0.1
CXXFLAGS="-Wno-narrowing -std=c++11" ./configure --disable-linuxmodule --enable-local --enable-etherswitch
popd