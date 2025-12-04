#!/bin/bash
set -e
echo "Verifying results..."

if [ ! -f sender_secret.hex ]; then
    echo "Error: sender_secret.hex not found. Run ./send.sh first."
    exit 1
fi

if [ ! -f secret.bin ]; then
    echo "Error: secret.bin not found. Run ./recover.sh first."
    exit 1
fi

SENDER=$(cat sender_secret.hex)
RECOVERED=$(cat secret.bin)

echo "Sender Secret:    $SENDER"
echo "Recovered Secret: $RECOVERED"

if [ "$SENDER" == "$RECOVERED" ]; then
    echo "SUCCESS: Secrets match!"
else
    echo "FAILURE: Secrets do not match."
    exit 1
fi
