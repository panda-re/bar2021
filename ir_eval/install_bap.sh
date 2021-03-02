#! /bin/bash

# https://github.com/BinaryAnalysisPlatform/bap#using-pre-build-packages
wget -q --show-progress https://github.com/BinaryAnalysisPlatform/bap/releases/download/v2.2.0/{bap,libbap,libbap-dev}_2.2.0.deb
sudo dpkg -i {bap,libbap,libbap-dev}_2.2.0.deb
rm {bap,libbap,libbap-dev}_2.2.0.deb