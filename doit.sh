#!/bin/bash
set -e
./keygen.sh
./send.sh
./recover.sh
./verify.sh
# ./clean.sh
#
