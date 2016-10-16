#!/bin/bash

# cd to the script directory
cd "$(dirname "$0")"

source env/bin/activate
python sonarwan/sonarwan.py --json $*
