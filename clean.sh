#!/bin/bash
set -e
echo "deleting old files..."
rm -f pk.pem chuck.key alice.key
rm -f ephemeral.pem sender_secret.hex
rm -f secret.bin
rm -f sender.log



