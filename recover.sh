#!/bin/bash
set -e
echo "Recipient recovering secret..."
go run mp-dh.go recover ephemeral.pem chuck.key alice.key secret.bin
echo "Recovered secret saved to: secret.bin"
