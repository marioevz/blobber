#!/bin/bash

echo "Testing the exact Kurtosis command..."

./blobber.bin \
  --beacon-port-start=9000 \
  --cl=http://localhost:4000 \
  --validator-key-folder=/tmp/test-keys/ \
  --enable-unsafe-mode \
  --external-ip=127.0.0.1 \
  --validator-proxy-port-start=5000 \
  --proposal-action='{"name": "blob_gossip_delay", "delay_milliseconds": 1500}' \
  --proposal-action-frequency=1