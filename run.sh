#!/bin/bash

# cd to the script directory
cd "$(dirname "$0")" || exit 1

source env/bin/activate
python sonarwan/sonarwan.py --json "$@"
