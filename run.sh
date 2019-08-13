#!/bin/sh
cd $(dirname $0)
"./faultreiber.py" --targetname autowasm --outdir ./test/ --structs ./test/struct.json --xml ./resources/wasm2.xml --name wasm --luaalloc --luaheaders ./lua/
#"./faultreiber.py" --targetname autowasm --outdir ./test/ --structs ./test/struct.json --xml ./resources/wasm2.xml --name wasm --calloc
"clang-format" -i ./test/read.c ./test/structs.c ./test/structs.h ./test/aggregate.c ./test/aggregate.h ./test/read.h
