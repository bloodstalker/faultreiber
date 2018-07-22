#!/bin/sh
cd $(dirname $0)
"./faultreiber.py" --targetname autowasm --outdir ./test/ --structs ./test/struct.json --datetime --structsinclude ./resources/structsinclude.h --xml ./resources/wasm.xml --inline --static
"clang-format" -i ./test/read.c ./test/structs.h
#"less" ./test/structs.h
