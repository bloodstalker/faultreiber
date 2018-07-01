#!/usr/bin/python3
# _*_ coding=utf-8 _*_

import argparse
import code
import fileinput
import json
import readline
from shutil import copy
import signal
import sys

def SigHandler_SIGINT(signum, frame):
    print()
    sys.exit(0)

class Argparser(object):
    def __init__(self):
        parser = argparse.ArgumentParser()
        parser.add_argument("--targetname", type=str, help="main target name")
        parser.add_argument("--outdir", type=str, help="path to output dir")
        parser.add_argument("--structs", type=str, help="the structs json file")
        parser.add_argument("--dbg", action="store_true", help="debug", default=False)
        self.args = parser.parse_args()

def dupemake(path, main_name):
    copy("./resources/makefile", path)
    makefile_path = str()
    if path[-1] == "/": makefile_path = path + "makefile"
    else: makefile_path = path + "/makefile"
    for line in fileinput.input(makefile_path, inplace=True):
        if "XXX" in line:
            line = line.replace("XXX", main_name)
        sys.stdout.write(line)

class CodeGen(object):
    def __init__(self, argparser):
        self.argparser = argparser
        self.struct_json = json.load(open(self.argparser.args.structs))

    def init_hook(self):
        pass

    def init(self):
        dupemake(self.argparser.args.outdir, self.argparser.args.targetname)

    def run(self):
        self.init()
        self.init_hook()

# write code here
def premain(argparser):
    signal.signal(signal.SIGINT, SigHandler_SIGINT)
    #here
    codegen = CodeGen(argparser)
    codegen.run()

def main():
    argparser = Argparser()
    if argparser.args.dbg:
        try:
            premain(argparser)
        except Exception as e:
            print(e.__doc__)
            if e.message: print(e.message)
            variables = globals().copy()
            variables.update(locals())
            shell = code.InteractiveConsole(variables)
            shell.interact(banner="DEBUG REPL")
    else:
        premain(argparser)

if __name__ == "__main__":
    main()
