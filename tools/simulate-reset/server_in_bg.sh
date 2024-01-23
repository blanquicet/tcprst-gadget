#!/bin/sh

# This script is used to simulate a HTTP server that listens on port 8000.
# Notice it is run in the background.

python3 -m http.server 8000 &
