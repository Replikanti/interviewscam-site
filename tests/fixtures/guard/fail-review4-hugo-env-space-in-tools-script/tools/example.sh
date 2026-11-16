#!/usr/bin/env bash
# A tools/ script that runs Hugo with a config variable whose delimiter is a space.
env "HUGO TITLE=Send it" "$HUGO_BIN" config
echo ok
