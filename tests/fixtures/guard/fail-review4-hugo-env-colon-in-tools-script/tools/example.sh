#!/usr/bin/env bash
# A tools/ script that runs Hugo with a config variable whose delimiter is a colon.
env "HUGO:TITLE=Send it" "$HUGO_BIN" config
echo ok
