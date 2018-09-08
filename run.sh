#!/bin/sh
cd $(dirname $0)
#"./faultreiber.py" --targetname autowasm --outdir ./test/ --structs ./test/struct.json --datetime --structsinclude ./resources/structsinclude.h --xml ./resources/wasm.xml
"./faultreiber.py" --targetname autowasm --outdir ./test/ --structs ./test/struct.json --xml ./resources/wasm.xml
"clang-format" -i ./test/read.c ./test/structs.c ./test/structs.h ./test/aggregate.c ./test/aggregate.h ./test/read.h
