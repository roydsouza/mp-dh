#!/bin/bash
set -e
echo "Sender performing DH..."
# Run send, capture output to log, and also display it
go run mp-dh.go send pk.pem ephemeral.pem > sender.log
cat sender.log

# Extract the secret for verification (assuming format "Sender Shared Secret (x-coord): <hex>")
grep "Sender Shared Secret" sender.log | awk '{print $5}' > sender_secret.hex
echo "Ephemeral key generated: ephemeral.pem"
echo "Sender secret saved to: sender_secret.hex"
