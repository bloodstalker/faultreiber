#!/usr/bin/bash
cd $(dirname $0)
if [[ -d ./out ]]; then :;else mkdir ./out;fi
./luatablegen/luatablegen.py --out ./out --luaheader ../test/lua --headeraggr ./out/wasm_tables.h --lualibpath ./out/wasm.lua --docpath ./out/wasm.md --xml ./luatablegen/test/luwasm.xml --tbldefs ./out/ --anon --name wasm --lualibname wasmextra
clang-format ./out/*.c ./out/*.h -i
for filename in ./out/*.c; do
  gcc -c $filename > /dev/null 2>&1
  if [[ $? != 0 ]]; then
    echo $filename did not compile.
  fi
done
rm *.o
