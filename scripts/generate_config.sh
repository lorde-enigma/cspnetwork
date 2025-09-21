#!/bin/bash

if [ $# -lt 1 ]; then
    echo "Usage: $0 <client_name> [seed_string]"
    echo "Example: $0 enigmaweb"
    echo "Example: $0 enigmaweb mysecretword"
    exit 1
fi

CLIENT_NAME="$1"
SEED_STRING="${2:-$CLIENT_NAME}"

echo "generating configuration for client: $CLIENT_NAME"
echo "using seed string: $SEED_STRING"

SEED_HASH=$(echo -n "$SEED_STRING" | sha256sum | cut -c1-16)
SEED_DECIMAL=$(echo "ibase=16; ${SEED_HASH^^}" | bc)

echo "seed hash: $SEED_HASH"
echo "seed decimal: $SEED_DECIMAL"

OUTPUT_FILE="${CLIENT_NAME}.cspvpn"

cspvpn-gen --name "$CLIENT_NAME" --seed "$SEED_DECIMAL" --output "$OUTPUT_FILE"

if [ $? -eq 0 ]; then
    echo "configuration generated successfully: $OUTPUT_FILE"
    echo "to connect: sudo cspvpn-client --config $OUTPUT_FILE"
else
    echo "failed to generate configuration"
    exit 1
fi
