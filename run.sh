#!/bin/sh
cd $(dirname $0)
"./faultreiber.py" --targetname autowasm --outdir ./test/ --structs ./test/struct.json --datetime --structsinclude ./resources/structsinclude.h
