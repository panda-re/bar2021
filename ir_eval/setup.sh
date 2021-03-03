#! /bin/bash

# Install BAP ----------------------------------------------------------------------------------------------------------

# https://github.com/BinaryAnalysisPlatform/bap#using-pre-build-packages
wget -q --show-progress https://github.com/BinaryAnalysisPlatform/bap/releases/download/v2.2.0/{bap,libbap,libbap-dev}_2.2.0.deb
sudo dpkg -i {bap,libbap,libbap-dev}_2.2.0.deb
rm {bap,libbap,libbap-dev}_2.2.0.deb

# Download Replays -----------------------------------------------------------------------------------------------------

wget -q --show-progress https://panda.re/ndss_bar_2021/whoami_arm-rr-nondet.log
wget -q --show-progress https://panda.re/ndss_bar_2021/whoami_arm-rr-snp
wget -q --show-progress https://panda.re/ndss_bar_2021/whoami_i386-rr-nondet.log
wget -q --show-progress https://panda.re/ndss_bar_2021/whoami_i386-rr-snp
wget -q --show-progress https://panda.re/ndss_bar_2021/whoami_x86_64-rr-nondet.log
wget -q --show-progress https://panda.re/ndss_bar_2021/whoami_x86_64-rr-snp

