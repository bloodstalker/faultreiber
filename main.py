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
from text import text
import datetime
import xml.etree.ElementTree
from misc import *

def SigHandler_SIGINT(signum, frame):
    print()
    sys.exit(0)

def get_full_path(path, name):
    if path[-1] == "/": return path + name
    else: return path + "/" + name

class Argparser(object):
    def __init__(self):
        parser = argparse.ArgumentParser()
        parser.add_argument("--targetname", type=str, help="main target name")
        parser.add_argument("--outdir", type=str, help="path to output dir")
        parser.add_argument("--structs", type=str, help="the structs json file")
        parser.add_argument("--structsinclude", type=str, help="the path to the header that's going to be included by structs.h before structure declarations.")
        parser.add_argument("--xml", type=str, help="paht to the xml file")
        parser.add_argument("--dbg", action="store_true", help="debug", default=False)
        parser.add_argument("--datetime", action="store_true", help="print date and time in autogen files", default=False)
        parser.add_argument("--inline", action="store_true", help="put all reads in sequentially", default=False)
        self.args = parser.parse_args()

def dupemake(path, main_name):
    copy("./resources/makefile", path)
    makefile_path = get_full_path(path, "makefile")
    for line in fileinput.input(makefile_path, inplace=True):
        if "XXX" in line:
            line = line.replace("XXX", main_name)
        sys.stdout.write(line)

class CodeGen(object):
    def __init__(self, argparser):
        self.argparser = argparser
        self.struct_json = json.load(open(self.argparser.args.structs))
        self.dnt = datetime.datetime.now().isoformat()

    def init_hook(self):
        pass

    def init(self):
        dupemake(self.argparser.args.outdir, self.argparser.args.targetname)

    def gen_reader_funcs(self):
        pass

    def read_xml(self):
        if self.argparser.args.xml:
            tree = xml.etree.ElementTree.parse(self.argparser.args.xml)
            root = tree.getroot()
            print(root.tag)
            print(root.attrib)
            read_tree = xml.etree.ElementTree.Element("read")
            def_tree = xml.etree.ElementTree.Element("def")
            for child in root:
                print(child.tag + "--" + repr(child.attrib))
                if child.tag == "Read":
                    read_tree = child
                    print(type(child))
                if child.tag == "Definition":
                    def_tree = child
                    print(type(child))
            print(read_tree.tag)
            print(def_tree.tag)
            read_iter = read_tree.iter(tag=None)
            def_iter = def_tree.iter(tag=None)
            for child in def_iter:
                print(child.attrib)
                for childer in child.iter(tag=None):
                    print("\t" + childer.tag + "--" + repr(childer.attrib))
            for child in read_iter:
                print(child.attrib)
                for childer in child.iter(tag=None):
                    print("\t" + childer.tag + "--" + repr(childer.attrib))

    def gen_struct_header(self):
        struct_source = open(get_full_path(self.argparser.args.outdir, "structs.h"), "w")
        struct_source_c = open(get_full_path(self.argparser.args.outdir, "structs.c"), "w")
        struct_source_c.write('#include "structs.h"')
        struct_source.write(text.pre_header_guard)
        struct_source.write(text.autogen_warning)
        if self.argparser.args.datetime: struct_source.write("// " + self.dnt + "\n")
        struct_source.write(text.header_guard_begin.replace("XXX", "structs".upper()))
        struct_source.write(text.header_inttype)
        if self.argparser.args.structsinclude:
            copy(self.argparser.args.structsinclude, self.argparser.args.outdir)
            pos = self.argparser.args.structsinclude.rfind("/")
            sub = self.argparser.args.structsinclude[pos+1:]
            struct_source.write('#include "' + sub + '"\n')
        for k,v in self.struct_json.items():
            struct_name = k
            field_names = v["field_name"]
            field_typess = v["field_type"]
            struct_source.write("typedef struct {\n")
            for i, j in zip(field_names, field_typess):
                struct_source.write("\t" + j + " " + i + ";\n")
            struct_source.write("}" + struct_name + ";\n\n")
        struct_source.write(text.pragma_endif)
        struct_source.write(text.last_comment)

    def run(self):
        self.init()
        self.init_hook()
        self.gen_struct_header()
        self.read_xml()

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
