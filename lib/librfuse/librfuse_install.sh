#!/bin/bash

rm -rf build
rm -rf /usr/local/include/fuse3
mkdir build
cd build
meson
ninja
sudo ninja install
cd ../
