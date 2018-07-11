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

# TODO-doesnt support non-byte-sized reads
def type_resolver(elem, elem_list):
    type_str = elem.attrib["type"]
    type_name = elem.attrib["name"]
    if type_str == "int8":
        return "int8_t"
    elif type_str == "uint8":
        return "uint8_t"
    elif type_str == "int16":
        return "int16_t"
    elif type_str == "uint16":
        return "uint16_t"
    elif type_str == "int32":
        return "int32_t"
    elif type_str == "uint32":
        return "uint32_t"
    elif type_str == "int64":
        return "int64_t"
    elif type_str == "uint64":
        return "uint64_t"
    elif type_str == "int128":
        return "int128_t"
    elif type_str == "uint128":
        return "uint128_t"
    elif type_str == "float":
        return "float"
    elif type_str == "double":
        return "double"
    elif type_str == "bool":
        return "unsigned char"
    elif type_str == "uchar":
        return "unsigned char"
    elif type_str == "schar":
        return "signed char"
    elif type_str == "string":
        return "char*"
    elif type_str == "FT::conditional":
        return "void*"
    elif type_str.find("self::") == 0:
        for node in elem_list:
            if elem.attrib["type"][6:] == node.tag:
                return node.attrib["name"]
    else: return type_str

def get_def_node(type_str, elem_list):
    for node in elem_list:
        if type_str == node.attrib["name"]:
            return node

def reader_generator(elem, elem_list):
    pass

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
        parser.add_argument("--verbose", action="store_true", help="verbose", default=False)
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
        self.elems = []
        self.def_elems = []
        self.read_elems = []
        self.read_iter = []
        self.def_iter = []

    def init_hook(self):
        pass

    def init(self):
        dupemake(self.argparser.args.outdir, self.argparser.args.targetname)

    def dump_elems(self):
        for elem in self.elems:
            print("XXXX " + elem.tag)
            print(elem.attrib)

    def dump_def_elems(self):
        for elem in self.def_elems:
            print("XXXX " + elem.tag)
            print(elem.attrib)

    def dump_read_elems(self):
        for elem in self.read_elems:
            print("XXXX " + elem.tag)
            print(elem.attrib)

    def gen_reader_funcs(self):
        read_source = open(self.argparser.args.outdir + "/read.c", "w")
        read_source.write(text.header_list)
        for elem in self.read_elems:
            read_source.write(text.c_read_elem_sig.replace("YYY", elem.attrib["name"]).replace("XXX", elem.attrib["name"]))
            read_source.write(text.c_function_dummy_dec.replace("XXX", elem.attrib["name"]))
            if "isaggregate" in elem.attrib:
                for child in elem:
                    ref_node_name = type_resolver(child, self.def_elems)
                    ref_node = get_def_node(ref_node_name, self.def_elems)
                    if ref_node:
                        read_source.write(text.c_read_elem_sig_1.replace("XXX", ref_node.attrib["name"]) + ";\n")
            else:
                read_source.write(type_resolver(elem, self.elems) + " " + elem.attrib["name"] + ";\n")
            read_source.write(text.c_function_return_type)
            read_source.write(text.c_function_close + "\n")

    def read_xml(self):
        if self.argparser.args.xml:
            def_header = open(self.argparser.args.outdir + "/defines.h", "w")
            def_header.write(text.header_inttype + "\n")
            tree = xml.etree.ElementTree.parse(self.argparser.args.xml)
            root = tree.getroot()
            read_tree = xml.etree.ElementTree.Element("read")
            def_tree = xml.etree.ElementTree.Element("def")
            for child in root:
                if child.tag == "Read":
                    read_tree = child
                if child.tag == "Definition":
                    def_tree = child
            for child in read_tree:
                self.read_elems.append(child)
            for child in def_tree:
                self.def_elems.append(child)
            read_iter = read_tree.iter(tag=None)
            def_iter = def_tree.iter(tag=None)
            self.read_iter = read_iter
            self.def_iter = def_iter
            for child in def_iter:
                self.elems.append(child)
                if "isaggregate" in child.attrib:
                    def_header.write("typedef struct {\n")
                    for childerer in child:
                        c_type = type_resolver(childerer, self.elems)
                        def_header.write("\t" + c_type + " " + childerer.attrib["name"] + ";\n")
                    def_header.write("}" + child.attrib["name"] + ";\n\n")
            for child in read_iter:
                self.elems.append(child)
                if "isaggregate" in child.attrib:
                    def_header.write("typedef struct {\n")
                    for childerer in child:
                        c_type = type_resolver(childerer, self.elems)
                        def_header.write("\t" + c_type + " " + childerer.attrib["name"] + ";\n")
                    def_header.write("}" + child.attrib["name"] + ";\n\n")

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
        self.gen_reader_funcs()
        #self.dump_def_elems()
        #print("")
        #self.dump_read_elems()

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
