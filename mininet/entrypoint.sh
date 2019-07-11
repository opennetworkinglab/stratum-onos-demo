#!/usr/bin/env bash

# Start mininet in a screen session so we can attach to its CLI later.
screen -dmS cli -L screen.log python topo.py

# Print CLI outoput to stdout as container log.
# Make sure to tail on an existing file if screen hasn't created yet
# the log file.
touch screen.log
tail -f screen.log
