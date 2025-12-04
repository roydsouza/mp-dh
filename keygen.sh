#!/bin/bash
set -e
echo "Generating keys..."
go run mp-dh.go generate pk.pem chuck.key alice.key
echo "Keys generated: pk.pem, chuck.key, alice.key"
