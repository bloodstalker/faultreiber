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
import os
from text import text
import datetime
import xml.etree.ElementTree
from misc import *
import datetime

# TODO-doesnt support non-byte-sized reads
# TODO-doesnt support big-endian normal reads
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
        return "uint8_t"
    elif type_str == "uchar":
        return "uint8_t"
    elif type_str == "schar":
        return "schar_t"
    elif type_str == "string":
        return "unsigned char*"
    elif type_str == "FT::conditional":
        return "void*"
    elif type_str.find("self::") == 0:
        for node in elem_list:
            if elem.attrib["type"][6:] == node.tag:
                return node.attrib["name"]
    else: return type_str

def get_malloc_size(node, elem_list):
    void_count = 0
    numeric_count = 0
    has_special = False
    for child in node:
        if type_str == "int8": numeric_count+=1
        elif type_str == "uint8": numeric_count+=1
        elif type_str == "int16": numeric_count+=2
        elif type_str == "uint16": numeric_count+=2
        elif type_str == "int32": numeric_count+=3
        elif type_str == "uint32": numeric_count+=3
        elif type_str == "int64": numeric_count+=8
        elif type_str == "uint64": numeric_count+=8
        elif type_str == "int128": numeric_count+=16
        elif type_str == "uint128": numeric_count+=16
        elif type_str == "float": numeric_count+=32
        elif type_str == "double": numeric_count+=64
        elif type_str == "bool": numeric_count+=1
        elif type_str == "uchar": numeric_count+=1
        elif type_str == "schar": numeric_count+=1
        elif type_str == "string": has_special = True
        elif type_str == "FT::conditional": pass
        elif type_str.find("self::") == 0: void_count+=1
        else: pass

def get_type_width(elem):
    type_str = str()
    try:
        type_str = elem.attrib["type"]
    except KeyError:
        print("xml node does not have a type attribute: " + elem.tag)
    if type_str == "int8": return 1
    elif type_str == "uint8": return 1
    elif type_str == "int16": return 2
    elif type_str == "uint16": return 2
    elif type_str == "int32": return 4
    elif type_str == "uint32": return 4
    elif type_str == "int64": return 8
    elif type_str == "uint64": return 8
    elif type_str == "int128": return 16
    elif type_str == "uint128": return 16
    elif type_str == "float": return 4
    elif type_str == "double": return 8
    elif type_str == "bool": return 1
    elif type_str == "uchar": return 1
    elif type_str == "schar": return 1
    elif type_str == "string": return 0
    elif type_str == "FT::conditional": return 0
    elif type_str.find("self::") == 0: return 0
    else: return 0

def get_def_node(type_str, elem_list):
    for node in elem_list:
        if type_str == node.attrib["name"]:
            return node

def pointer_remover(name:str):
    if name[-1] == '*': return name[0:-1] + '_p'
    else: return name

def get_node_name(tag, elem_list):
    for elem in elem_list:
        if tag == elem.tag: return elem.attrib["name"]

def reader_generator(elem, elem_list):
    pass

def SigHandler_SIGINT(signum, frame):
    print()
    sys.exit(0)

def get_full_path(path, name):
    if path[-1] == "/": return path + name
    else: return path + "/" + name

def get_elem_count(elem):
    if "count" in elem.attrib:
        try:
            if str(int(elem.attrib["count"])) == elem.attrib["count"]:
                return int(elem.attrib["count"])
            else: return -1
        except ValueError:
            return -1
    else:
        return 1

def get_elem_size(elem):
    if "size" in elem.attrib:
        try:
            if str(int(elem.attrib["size"])) == elem.attrib["size"]:
                return int(elem.attrib["size"])
        except ValueError:
            return -1
    else:
        return 0

def get_encoding_read(encoding):
    if encoding == "leb128u":
        return text.c_read_leb_128_u
    elif encoding == "leb128s":
        return text.c_read_leb_128_s
    else: pass

class Argparser(object):
    def __init__(self):
        parser = argparse.ArgumentParser()
        parser.add_argument("--targetname", type=str, help="main target name")
        parser.add_argument("--outdir", type=str, help="path to output dir")
        parser.add_argument("--structs", type=str, help="the structs json file")
        parser.add_argument("--structsinclude", type=str, help="the path to the header that's going to be included by structs.h before structure declarations.")
        parser.add_argument("--xml", type=str, help="paht to the xml file")
        parser.add_argument("--name", type=str, help="will be used to create some names in the source code")
        parser.add_argument("--dbg", action="store_true", help="debug", default=False)
        parser.add_argument("--datetime", action="store_true", help="print date and time in autogen files", default=False)
        parser.add_argument("--inline", action="store_true", help="inlines reader funcs", default=False)
        parser.add_argument("--static", action="store_true", help="statics reader funcs", default=False)
        parser.add_argument("--verbose", action="store_true", help="verbose", default=False)
        parser.add_argument("--forcenullterm", action="store_true", help="terminate all strings with null even if they are not originally null-terminated", default=False)
        parser.add_argument("--voidtraininitsize", type=int, help="the size of the void train, an integer", default=100)
        parser.add_argument("--voidtrainfactor", type=float, help="the factor by which the voidtrain will grow, a float", default=2.0)
        parser.add_argument("--singlefile", action="store_true", help="the generated code will be put in a single file", default=False)
        parser.add_argument("--calloc", action="store_true", help="use calloc instead of malloc, defaults to false", default=False)
        parser.add_argument("--luaalloc", action="store_true", help="use calloc instead of malloc, defaults to false", default=False)
        parser.add_argument("--luaheaders", type=str, help="the location of lua header files that need to get added to the lib files if luaalloc has been selected", default="")
        parser.add_argument("--singlefilename", type=str, help="name of the single file")
        self.args = parser.parse_args()
        if self.args.calloc and self.args.luaalloc: print("you have selected both calloc and lua_newuserdata. that can't possibly work.\n")

class C_Obj():
    def __init__(self, str, ancestry):
        self.malloc = str
        self.ancestry = ancestry

def get_script_path():
    return os.path.dirname(os.path.realpath(sys.argv[0]))

def dupemake(path, main_name):
    os.chdir(get_script_path())
    copy("./resources/makefile", path)
    makefile_path = get_full_path(path, "makefile")
    for line in fileinput.input(makefile_path, inplace=True):
        if "XXX" in line:
            line = line.replace("XXX", main_name)
        sys.stdout.write(line)

class CodeGen(object):
    def __init__(self, argparser):
        self.argparser = argparser
        self.dnt = datetime.datetime.now().isoformat()
        print(self.dnt)
        self.elems = []
        self.def_elems = []
        self.read_elems = []
        self.read_iter = []
        self.def_iter = []
        self.mem_size = {}
        self.tree = xml.etree.ElementTree.parse(self.argparser.args.xml)
        self.root = self.tree.getroot()
        self.aggregate_source = ""
        self.aggregate_source_h = ""
        self.aggregate_flags = ""
        self.read_source = ""
        self.read_flags = ""
        self.struct_source = ""
        self.struct_flags = ""
        self.malloc_list = []

    def file_manager(self):
        if self.argparser.args.singlefile:
            name = self.argparser.args.singlefilename
            self.read_source = self.argparser.args.outdir + "/" + name
            self.aggregate_source = self.argparser.args.outdir + "/" + name
            self.struct_source = self.argparser.args.outdir + "/" + name
        else:
            self.read_source = self.argparser.args.outdir + "/read.c"
            self.aggregate_source = self.argparser.args.outdir + "/aggregate.c"
            self.aggregate_source_h = self.argparser.args.outdir + "/aggregate.h"
            self.struct_source_h = self.argparser.args.outdir + "/structs.h"
            self.struct_source = self.argparser.args.outdir + "/structs.c"

    def init_hook(self):
        pass

    def init(self):
        #dupemake(self.argparser.args.outdir, self.argparser.args.targetname)
        pass

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

    def dump_mem_dict(self):
        for key, value in self.mem_size.items():
            print(key + ".." + value)

    def dump_all_childs(self):
        for node in self.root.iter():
            print(node.tag)

    def dump_malloc(self):
        for obj in self.malloc_list:
            print(obj.malloc + ":" + str(obj.ancestry))

    def gen_reader_funcs(self, alloc):
        temp_dec_list = []
        lua_udata_set = self.argparser.args.luaalloc

        read_source = open(self.read_source, "w")
        read_source.write("\n// automatically generated by faultrieber\n")
        read_source.write("// " + self.dnt + "\n\n")
        read_source.write(text.header_list)
        if self.argparser.args.luaalloc:
            read_source.write('#include "'+self.argparser.args.luaheaders+'"\n')
        read_source.write('#include "./read.h"\n')
        read_source.write('#include "./structs.h"\n\n')
        if self.argparser.args.calloc: read_source.write(text.ft_calloc_def)
        if self.argparser.args.luaalloc: read_source.write(text.ft_luanewuserdata_def)
        read_sig_zzz = str()
        read_proto_zzz = str()
        if self.argparser.args.luaalloc:
            read_sig_zzz = "lua_State* __ls"
            read_proto_zzz = "__ls"
        else:
            read_sig_zzz = "void*** void_train"
            read_proto_zzz = "void_train"
        inline = "inline " if self.argparser.args.inline else ""
        static = "static " if self.argparser.args.static else ""
        for elem in self.def_elems + self.read_elems:
            dummy_list = []
            dummy_string = str()
            pointer = str()
            access = "."
            dummy_static = str()
            count_version = False
            count_version_buffer = str()
            if "isaggregate" in elem.attrib:
                #pointer = "*"
                pointer = ""
                access = "->"
                dummy_static = ""
            if "isaggregate" in elem.attrib:
                # setting count_version here
                if "countversion" in elem.attrib: count_version = True
                else: count_version = False
                dummy_string += ", " + elem.attrib["name"] + "*"  + " dummy_" + elem.attrib["name"]
                read_source.write(static + inline + text.c_read_elem_sig.replace("YYY", elem.attrib["name"]).replace("XXX", elem.attrib["name"]+pointer).replace("ZZZ", read_sig_zzz))
                read_source.write("*dummy = "+alloc+"(sizeof(" + elem.attrib["name"] + "));\n")
                read_source.write("uint64_t b_count = 0;\n")
                if count_version:
                    count_version_buffer = static + inline + text.c_read_elem_sig_c.replace("YYY", elem.attrib["name"]).replace("XXX", elem.attrib["name"]+pointer).replace("ZZZ", read_sig_zzz)
                    count_version_buffer += "*dummy = "+alloc+"(sizeof(" + elem.attrib["name"] + "));\n"
                    count_version_buffer += "uint64_t b_count = 0;\n"
                for sub in elem:
                    if "sizeconst" in sub.attrib:
                        read_source.write("uint64_t agg_b_count = 0;\n")
                        break
                if not lua_udata_set:
                    read_source.write(text.c_void_manager_proto.replace("XXX", "(*dummy)"));
                else:
                    read_source.write(text.lua_udata_regindex.replace("XXX", elem.attrib["name"]).replace("YYY","(*dummy)"))
                if not lua_udata_set:
                    if count_version:
                        count_version_buffer += text.c_void_manager_proto.replace("XXX", "(*dummy)")
                else:
                    if count_version:
                        count_version_buffer += text.lua_udata_regindex.replace("XXX", elem.attrib["name"]).replace("YYY", "(*dummy)")
                self.malloc_list.append(C_Obj(elem.attrib["name"], [elem.tag]))
                count = get_elem_count(elem)
                if count == 1 or count != 1:
                    for child in elem:
                        child_count = get_elem_count(child)
                        ref_node_name = type_resolver(child, self.def_elems)
                        ref_node = get_def_node(ref_node_name, self.def_elems)
                        size = get_elem_size(child)
                        read_size_replacement = str()
                        if size > 0:
                            read_size_replacement = str(size)
                        if size == -1:
                            if "delimiter" in child.attrib:
                                ref_size = ""
                            else:
                                ref_size = "(*dummy)->" + get_node_name(child.attrib["size"][6:], elem)
                        if "conditional" in child.attrib:
                            cond_name = get_node_name(child.attrib["condition"][6:], elem)
                            for cond in child:
                                child_count = get_elem_count(cond)
                                ref_node_name = type_resolver(cond, self.def_elems)
                                ref_node = get_def_node(ref_node_name, self.def_elems)
                                if ref_node:
                                    read_source.write("if ((*dummy)->" + cond_name + "==" + str(cond.text) + "){\n")
                                    read_source.write("(*dummy)->" + cond.attrib["name"] + "="+alloc+"(sizeof(" + ref_node.attrib["name"] + "));")
                                    if not lua_udata_set: read_source.write(text.c_void_manager_proto.replace("XXX", "(*dummy)->" + cond.attrib["name"]));
                                    else: read_source.write(text.lua_udata_regindex.replace("XXX", elem.attrib["name"]).replace("YYY", "(*dummy)"))
                                    self.malloc_list.append(C_Obj(ref_node.attrib["name"], [elem.tag, child.tag]))
                                    if child_count == 1:
                                        for_read = text.c_read_elem_sig_2.replace("XXX", ref_node_name).replace("YYY", "&(*dummy)->" + cond.attrib["name"]).replace("ZZZ", read_proto_zzz) + ";\n"
                                        read_source.write(for_read)
                                        if count_version:
                                            count_version_buffer += for_read
                                    elif child_count > 1:
                                        for_read = text.c_read_elem_sig_2.replace("XXX", ref_node_name).replace("YYY", "&(*dummy)->" + cond.attrib["name"] + "[i]").replace("ZZZ", read_proto_zzz) + ";\n"
                                        if count_version:
                                            count_version_buffer += for_read
                                        read_source.write(for_read)
                                    else: # child_count == -1
                                        count_name_str = cond.attrib["count"][6:]
                                        read_source.write("if (" + "(*dummy)->" + get_node_name(count_name_str, elem) + ")\n")
                                        read_source.write("(*dummy)->" + cond.attrib["name"] + " = " + alloc+"(sizeof(void*)*" + "(*dummy)->" + get_node_name(count_name_str, child) + ");\n")
                                        if not lua_udata_set: read_source.write(text.c_void_manager_proto.replace("XXX", "(*dummy)->" + cond.attri["name"]));
                                        self.malloc_list.append(C_Obj("sizeof(void*)*(*dummy)->"+get_node_name(count_name_str, child), [elem.attrib["name"], child.attrib["name"], cond.arrtib["name"]]))
                                        for_read = text.c_read_elem_sig_2.replace("XXX", ref_node_name).replace("YYY", "&(*dummy)->" + cond.attrib["name"] + "[i]").replace("ZZZ", read_proto_zzz) + ";\n"
                                        read_source.write(text.simple_loop.replace("YYY", for_read).replace("XXX", "(*dummy)->" + get_node_name(count_name_str, child)))
                                    read_source.write("}\n")
                                    if count_version:
                                        count_version_buffer += for_read + "}\n"
                                else:
                                    read_source.write("if ((*dummy)->" + cond_name + "==" + str(cond.text) + "){\n")
                                    read_source.write("(*dummy)->" + cond.attrib["name"] + "="+alloc+"(sizeof(" + ref_node_name  + "));")
                                    if not lua_udata_set: read_source.write(text.c_void_manager_proto.replace("XXX", "(*dummy)->" + cond.attrib["name"]));
                                    for_read = str()
                                    if child_count == 1: array_subscript = ""
                                    elif child_count > 1: array_subscript = "[i]"
                                    else: array_subscript = "[i]"
                                    if "size" in cond.attrib:
                                        if "encoding" in cond.attrib:
                                            for_read = "(*dummy)->" + cond.attrib["name"] + array_subscript + "=" + get_encoding_read(cond.attrib["encoding"])
                                        else:
                                            if cond.attrib["name"] == "string":
                                                for_read = "(*dummy)->" + cond.attrib["name"] + " = " + alloc+"(" + ref_size + "+1);\n"
                                                if not lua_udata_set: read_source.write(text.c_void_manager_proto.replace("XXX", "(*dummy)->" + cond.attrib["name"]));
                                                for_read += "(*dummy)->" + cond.attrib["name"] + "["+ref_size+"]=" + "0;\n"
                                                for_read = text.c_read_gen_2_no.replace("XXX", "(*dummy)" + "->"+ cond.attrib["name"] + array_subscript).replace("YYY", ref_size)
                                            else:
                                                for_read = text.c_read_gen_2.replace("XXX", "(*dummy)" + "->"+ cond.attrib["name"] + array_subscript).replace("YYY", ref_size)
                                    else:
                                        if "encoding" in cond.attrib:
                                            for_read = "(*dummy)->" + cond.attrib["name"] + array_subscript + " = " + get_encoding_read(cond.attrib["encoding"])
                                        else:
                                            if cond.attrib["type"] == "string":
                                                for_read = text.c_read_gen_no.replace("XXX", "(*dummy)" + "->" + cond.attrib["name"] + array_subscript).replace("YYY", ref_node_name)
                                            else:
                                                for_read = text.c_read_gen.replace("XXX", "(*dummy)" + "->" + cond.attrib["name"] + array_subscript).replace("YYY", ref_node_name)
                                    if child_count == 1:
                                        read_source.write(for_read)
                                    elif child_count > 1:
                                        read_source.write(text.simple_loop.replace("YYY", for_read).replace("XXX", str(child_count)))
                                    else: # child_count = -1
                                        count_name_str = cond.attrib["count"][6:]
                                        read_source.write("(*dummy)->" + cond.attrib["name"] + " = " + alloc+"(sizeof(" + type_resolver(cond, self.def_elems + self.read_elems)  + ")*" + "(*dummy)->" + get_node_name(count_name_str, elem) + ");\n")
                                        if not lua_udata_set: read_source.write(text.c_void_manager_proto.replace("XXX", "(*dummy)->" + cond.attrib["name"]));
                                        read_source.write("if (" + "(*dummy)->" + get_node_name(count_name_str, child) + ")\n")
                                        read_source.write(text.simple_loop.replace("YYY", for_read).replace("XXX", "(*dummy)->" + get_node_name(count_name_str, elem)))
                                    read_source.write("}\n")
                            continue
                        if ref_node:
                            ref_node_name = pointer_remover(ref_node.attrib["name"])
                            if child_count == 1:
                                if "sizeconst" in child.attrib:
                                    if "sizeconst" != "end":
                                        for_read = text.c_read_elem_sig_2_c.replace("XXX", ref_node_name).replace("YYY", "&(*dummy)->" + child.attrib["name"]).replace("ZZZ", read_proto_zzz) + ";\n"
                                else:
                                    for_read = text.c_read_elem_sig_2.replace("XXX", ref_node_name).replace("YYY", "&(*dummy)->" + child.attrib["name"]).replace("ZZZ", read_proto_zzz) + ";\n"
                                read_source.write("(*dummy)->" + child.attrib["name"] + "=" + for_read)
                                if count_version:
                                    count_version_buffer += "(*dummy)->" + child.attrib["name"] + "=" + for_read
                            elif child_count > 1:
                                if "sizeconst" in child.attrib:
                                    if "sizeconst" != "end":
                                        for_read = text.c_read_elem_sig_2_c.replace("XXX", ref_node_name).replace("YYY", "&(*dummy)->" + child.attrib["name"] + "[i]").replace("ZZZ", read_proto_zzz) + ";\n"
                                else:
                                    for_read = text.c_read_elem_sig_2.replace("XXX", ref_node_name).replace("YYY", "&(*dummy)->" + child.attrib["name"] + "[i]").replace("ZZZ", read_proto_zzz) + ";\n"
                                read_source.write("(*dummy)->" + child.attrib["name"] + "=" + for_read)
                                if count_version:
                                    count_version_buffer += "(*dummy)->" + child.attrib["name"] + "=" + for_read
                            else: # child_count == -1
                                count_name_str = child.attrib["count"][6:]
                                read_source.write("if (" + "(*dummy)->" + get_node_name(count_name_str, elem) + ")\n")
                                read_source.write("(*dummy)->" + child.attrib["name"] + " = " +alloc+"(sizeof(void*)*" + "(*dummy)->" + get_node_name(count_name_str, elem) + ");\n")
                                if not lua_udata_set: read_source.write(text.c_void_manager_proto.replace("XXX", "(*dummy)->" + child.attrib["name"]));
                                if "sizeconst" in child.attrib:
                                    if "sizeconst" != "end":
                                        for_read = text.c_read_elem_sig_2_c.replace("XXX", ref_node_name).replace("YYY", "&(*dummy)->" + child.attrib["name"] + "[i]").replace("ZZZ", read_proto_zzz)+ ";\n"
                                else:
                                    for_read = text.c_read_elem_sig_2.replace("XXX", ref_node_name).replace("YYY", "&(*dummy)->" + child.attrib["name"] + "[i]").replace("ZZZ", read_proto_zzz) + ";\n"
                                read_source.write(text.simple_loop.replace("YYY", "(*dummy)->" + child.attrib["name"] + "[i]=" + for_read).replace("XXX", "(*dummy)->" + get_node_name(count_name_str, elem)))
                                if count_version:
                                    count_version_buffer += text.simple_loop.replace("YYY", "(*dummy)->" + child.attrib["name"] + "[i]=" + for_read).replace("XXX", "(*dummy)->" + get_node_name(count_name_str, elem))
                            if "sizeconst" in child.attrib:
                                #read_source.write("XXXXX;\n")
                                pass
                        else:
                            for_read = str()
                            if child_count == 1: array_subscript = ""
                            elif child_count > 1: array_subscript = "[i]"
                            else: array_subscript = "[i]"
                            if "size" in child.attrib:
                                if "encoding" in child.attrib:
                                    for_read = "(*dummy)->" + child.attrib["name"] + array_subscript + "=" + get_encoding_read(child.attrib["encoding"])
                                    if "sizeconst" in child.attrib:
                                        if child.attrib["sizeconst"] != "end":
                                            for_read += "agg_b_count += b_count;"
                                else:
                                    if child.attrib["type"] == "string":
                                        if "delimiter" in child.attrib:
                                            delimiter = child.attrib["delimiter"]
                                            for_read = "int32_t " + child.attrib["name"] + "_del_pos =" + text.c_read_until_delimiter_proto.replace("XXX", delimiter) + ";\n"
                                            for_read += "(*dummy)->" + child.attrib["name"] + "=" +alloc+"(" + child.attrib["name"] + "_del_pos + 1);\n"
                                            if not lua_udata_set: for_read +=text.c_void_manager_proto.replace("XXX", "(*dummy)->" + child.attrib["name"]);
                                            for_read += text.c_read_gen_2_no.replace("XXX", "(*dummy)" + "->"+ child.attrib["name"] + array_subscript).replace("YYY", child.attrib["name"]+"_del_pos")
                                            for_read += "(*dummy)->" + child.attrib["name"] + "[" + child.attrib["name"] + "_del_pos] = 0;\n"
                                        else:
                                            for_read = "(*dummy)->" + child.attrib["name"] + " = " + alloc+"(" + ref_size + "+1);\n"
                                            if not lua_udata_set: for_read += text.c_void_manager_proto.replace("XXX", "(*dummy)->" + child.attrib["name"]);
                                            for_read += "(*dummy)->" + child.attrib["name"] + "["+ref_size+"]=" + "0;\n"
                                            for_read += text.c_read_gen_2_no.replace("XXX", "(*dummy)" + "->"+ child.attrib["name"] + array_subscript).replace("YYY", ref_size)
                                    else:
                                        for_read = text.c_read_gen_2.replace("XXX", "(*dummy)" + "->"+ child.attrib["name"] + array_subscript).replace("YYY", ref_size)
                            else:
                                if "encoding" in child.attrib:
                                    for_read = "(*dummy)->" + child.attrib["name"] + array_subscript + " = " + get_encoding_read(child.attrib["encoding"])
                                    if "sizeconst" in child.attrib:
                                        if child.attrib["sizeconst"] != "end":
                                            for_read += "agg_b_count += b_count;"
                                else:
                                    if child.attrib["type"] == "string":
                                        for_read = text.c_read_gen_no.replace("XXX", "(*dummy)" + "->" + child.attrib["name"] + array_subscript).replace("YYY", ref_node_name)
                                    else:
                                        for_read = text.c_read_gen.replace("XXX", "(*dummy)" + "->" + child.attrib["name"] + array_subscript).replace("YYY", ref_node_name)
                            if child_count == 1:
                                read_source.write(for_read)
                                if count_version:
                                    count_version_buffer += for_read
                                    count_version_buffer += "(*agg_b_count) += b_count;"
                            elif child_count > 1:
                                read_source.write(text.simple_loop.replace("YYY", for_read).replace("XXX", str(child_count)))
                                if count_version:
                                    count_version_buffer += text.simple_loop.replace("YYY", for_read).replace("XXX", str(child_count))
                                    count_version_buffer += "(*agg_b_count) += b_count;"
                            else: # child_count = -1
                                count_name_str = child.attrib["count"][6:]
                                read_source.write("(*dummy)->" + child.attrib["name"] + " = " +alloc+"(sizeof(" + type_resolver(child, self.def_elems + self.read_elems)  + ")*" + "(*dummy)->" + get_node_name(count_name_str, elem) + ");\n")
                                if not lua_udata_set: read_source.write(text.c_void_manager_proto.replace("XXX", "(*dummy)->" + child.attrib["name"]));
                                read_source.write("if (" + "(*dummy)->" + get_node_name(count_name_str, elem) + ")\n")
                                if count_version:
                                    count_version_buffer += "(*dummy)->" + child.attrib["name"] + " = " +alloc+"(sizeof(" + type_resolver(child, self.def_elems + self.read_elems)  + ")*" + "(*dummy)->" + get_node_name(count_name_str, elem) + ");\n"
                                    if not lua_udata_set: count_version_buffer += text.c_void_manager_proto.replace("XXX", "(*dummy)->" + child.attrib["name"])
                                    count_version_buffer += "if (" + "(*dummy)->" + get_node_name(count_name_str, elem) + ")\n"
                                    count_version_buffer += "(*agg_b_count) += b_count;"
                                if "sizeconst" in child.attrib:
                                    if child.attrib["sizeconst"] == "end":
                                        read_source.write(text.simple_loop.replace("YYY", for_read).replace("XXX", "(*dummy)->" + get_node_name(count_name_str, elem) + "- agg_b_count"))
                                else:
                                    read_source.write(text.simple_loop.replace("YYY", for_read).replace("XXX", "(*dummy)->" + get_node_name(count_name_str, elem)))
                # count != 1
                else:
                    pass
            # if not aggregate
            # if its an aggregate type there is only a single element in the
            # read funtion so we dont really need to worry about multiple
            # instances with the same name
            else:
                read_source.write(static + inline + text.c_read_elem_sig.replace("YYY", elem.attrib["name"]).replace("XXX", elem.attrib["name"]+pointer).replace("ZZZ", read_sig_zzz))
                read_source.write("*dummy = "+alloc+"(sizeof(" + elem.attrib["name"] + "));\n")
                if not lua_udata_set: read_source.write(text.c_void_manager_proto.replace("XXX", "*dummy"));
                read_source.write(text.c_read_gen.replace("XXX", "(*dummy)->" + elem.attrib["name"]).replace("YYY", type_resolver(elem, self.def_elems)))
            if "sizeconst" in child.attrib:
                read_source.write("agg_b_count=0;\n")
            if count_version:
                count_version_buffer += "return *dummy;\n"
                count_version_buffer += text.c_function_close + "\n"
            read_source.write("return *dummy;\n")
            read_source.write(text.c_function_close + "\n")
            if count_version:
                read_source.write(count_version_buffer)
        read_source_header = open(self.argparser.args.outdir + "/read.h", "w")
        read_source_header.write("\n// automatically generated by faultrieber\n")
        read_source_header.write("// " + self.dnt + "\n\n")
        read_source_header.write("#ifndef FT_READ_H\n#define FT_READ_H\n")
        read_source_header.write('#ifdef __cplusplus\nextern "C" {\n#endif\n')
        read_source_header.write('#include "./structs.h"\n')
        if self.argparser.args.luaalloc:
            read_source_header.write('#include "'+self.argparser.args.luaheaders+'"\n')
        for elem in self.def_elems + self.read_elems:
            read_source_header.write(static + inline + text.c_read_elem_sig_h.replace("YYY", elem.attrib["name"]).replace("XXX", elem.attrib["name"]).replace("ZZZ", read_sig_zzz))
            if "countversion" in elem.attrib:
                read_source_header.write(static + inline + text.c_read_elem_sig_h_c.replace("YYY", elem.attrib["name"]).replace("XXX", elem.attrib["name"]).replace("ZZZ", read_sig_zzz))
        read_source_header.write('#ifdef __cplusplus\n}\n#endif\n')
        read_source_header.write("#endif //end of header guard\n\n")

    def gen_void_train(self, alloc):
        void_source = open(self.aggregate_source, "w")
        void_source_h = open(self.aggregate_source_h, "w")
        void_source.write("\n// automatically generated by faultreiber\n")
        void_source_h.write("\n// automatically generated by faultreiber\n")
        void_source.write("// " + self.dnt + "\n")
        void_source_h.write("// " + self.dnt + "\n")
        void_source.write('#include "./structs.h"\n')
        void_source.write('#include "./read.h"\n')
        void_source.write("#include <stdlib.h>\n")
        void_source.write('#include "aggregate.h"\n')
        if self.argparser.args.calloc: void_source.write(text.ft_calloc_def)
        #void_source.write("void** void_train;\n")
        #void_source.write("uint64_t current_void_size = 0U;\n")
        #void_source.write("uint64_t current_void_count = 0U;\n")
        void_source_h.write('#ifndef FT_AGGREGATE_H\n#define FT_AGGREGATE_H\n')
        void_source_h.write('#ifdef __cplusplus\nextern "C" {\n#endif\n')
        void_source_h.write('#include "./structs.h"\n')
        # generating the extern declarations and definitions
        void_source_h.write("typedef struct {\n")
        for elem in self.read_elems:
            count = get_elem_count(elem)
            size = get_elem_size(elem)
            if count != 1:
                void_source_h.write(elem.attrib["name"] + "** " + elem.attrib["name"] + "_container;\n")
                #void_source.write(elem.attrib["name"] + "** " + elem.attrib["name"] + "_container;\n")
            else:
                void_source_h.write(elem.attrib["name"] + "* " + elem.attrib["name"] + "_container;\n")
                #void_source.write(elem.attrib["name"] + "* " + elem.attrib["name"] + "_container;\n")
        void_source_h.write("}" + self.argparser.args.name + "_obj_t;\n")
        #void_source_h.write(self.argparser.args.name + "_obj_t* obj;\n")
        void_source_h.write("typedef struct {\n")
        void_source_h.write(self.argparser.args.name + "_obj_t* obj;\n")
        void_source_h.write("void** void_train;\n")
        void_source_h.write("uint64_t current_void_size;\n")
        void_source_h.write("uint64_t current_void_count;\n")
        void_source_h.write("}" + self.argparser.args.name + "_lib_ret_t;\n")
        # end
        #void_source.write("void malloc_all(void) {\n")
        #void_source_h.write("void malloc_all(void);\n")
        count_int = int()
        count_void = int()
        read_count = len(self.read_elems)
        extern = ""
        # FIXME-count and size present together is not being handled at all
        for elem in self.read_elems:
            if "isaggregate" in elem.attrib:
                for child in elem:
                    ref_node_name = type_resolver(child, self.def_elems)
                    ref_node = get_def_node(ref_node_name, self.def_elems)
                    if ref_node: count_void+=1
                    count = get_elem_count(child)
                    size = get_elem_size(child)
                    type_width = get_type_width(child)
                    if count > 0: count_int+=count*type_width
                    if count < 0: count_void+=1
                    if size > 0: count_int+=size
                    if size < 0: count_void+=1
                sizeof = (str(count_int) if count_int > 0 else ("")) + ("+" if count_void>0 and count_int>0 else "") + ((str(count_void)+"*"+"sizeof(void*)") if count_void > 0 else "")
                count_int = 0
                count_void = 0
            else:
                ref_node_name = type_resolver(elem, self.def_elems)
                ref_node = get_def_node(ref_node_name, self.def_elems)
                if ref_node: count_void+=1
                if "size" in elem.attrib:
                    count = get_elem_count(elem)
                    if count > 0: count_int+= count
                    else: count_void+=1
                if "count" in elem.attrib:
                    size = get_elem_size(elem)
                    if size > 0: count_int+=size
                    else: count_void+=1
                sizeof = (str(count_int)+"+" if count_int > 0 else "") + (str(count_void)+"*"+"sizeof(void*)") if count_void > 0 else ""
                count_int = 0
                count_void = 0
        #void_source.write("}\n")
        void_source.write(self.argparser.args.name + "_lib_ret_t* read_aggr_"+self.argparser.args.name+"(int _fd) {\n")
        void_source.write("register " + self.argparser.args.name + "_lib_ret_t* lib_ret = "+alloc+"(sizeof("+self.argparser.args.name+"_lib_ret_t"+"));\n")
        void_source.write("lib_ret->obj = "+alloc+"(sizeof("+self.argparser.args.name+"_obj_t"+"));\n")
        for elem in self.read_elems:
            if "isaggregate" in elem.attrib:
                for child in elem:
                    ref_node_name = type_resolver(child, self.def_elems)
                    ref_node = get_def_node(ref_node_name, self.def_elems)
                    if ref_node:
                        pass
                        #void_source.write(elem.attrib["name"] + "_container->" + child.attrib["name"] + " = " + elem.attrib["name"] + "_" + child.attrib["name"] + "_container"  + ";\n")

    def gen_aggregate_read(self):
        agg_source = open(self.aggregate_source, "a")
        agg_source_h = open(self.aggregate_source_h, "a")
        #print(self.argparser.args.name)
        #agg_source.write('#include "aggregate.h"\n')
        agg_source_h.write(self.argparser.args.name + "_lib_ret_t* read_aggr_"+self.argparser.args.name+"(int _fd);\n")
        agg_source.write("uint8_t eof = 0U;")
        agg_source.write("lib_ret->current_void_count = 0;\n")
        agg_source.write("lib_ret->current_void_size = 0;\n")
        for elem in self.read_elems:
            if "unorderedbegin" in elem.attrib:
                agg_source.write("do {\n")

            if "unordered" in elem.attrib:
                if elem.attrib["count"] != "*":
                    for child in elem:
                        if "issign" in child.attrib:
                            sign_type = type_resolver(child, self.def_elems+ self.read_elems)
                            sign_name = " dummy_" + child.attrib["name"] + elem.attrib["name"]
                            agg_source.write("if (read(_fd, &eof, 1)<0) break;\nelse lseek(_fd, -1, SEEK_CUR);\n")
                            agg_source.write(sign_type + sign_name + ";\n")
                            agg_source.write(text.c_read_gen.replace("XXX", sign_name).replace("YYY", sign_type))
                            agg_source.write("lseek(_fd, -sizeof(" + sign_type + "), SEEK_CUR);\n")
                            agg_source.write("if (" + sign_name + "==" + child.text + "){\n")
                else: #count = "*"
                    for child in elem:
                        if "issign" in child.attrib:
                            sign_type = type_resolver(child, self.def_elems+ self.read_elems)
                            sign_name = " dummy_" + child.attrib["name"] + elem.attrib["name"]
                            agg_source.write("uint64_t " + elem.attrib["name"] + "_agg_count = 0U;\n")
                            agg_source.write("if (read(_fd, &eof, 1)<0) break;\nelse lseek(_fd, -1, SEEK_CUR);\n")
                            agg_source.write(sign_type + sign_name + ";\n")
                            agg_source.write(text.c_read_gen.replace("XXX", sign_name).replace("YYY", sign_type))
                            agg_source.write("lseek(_fd, -sizeof(" + sign_type + "), SEEK_CUR);\n")
                            agg_source.write("if (" + sign_name + "==" + child.text + "){\n")
            if elem.attrib["count"] != "*":
                if self.argparser.args.luaalloc:
                    agg_source.write("lib_ret->obj->"+elem.attrib["name"] + "_container = " + "ft_read_" + elem.attrib["name"] + "(_fd, &lib_ret->obj->" + elem.attrib["name"] + "_container, "  + "__ls, &lib_ret->current_void_size, &lib_ret->current_void_count);\n")
                else:
                    agg_source.write("lib_ret->obj->"+elem.attrib["name"] + "_container = " + "ft_read_" + elem.attrib["name"] + "(_fd, &lib_ret->obj->" + elem.attrib["name"] + "_container, "  + "&lib_ret->void_train, &lib_ret->current_void_size, &lib_ret->current_void_count);\n")
            else:
                if self.argparser.args.luaalloc:
                    agg_source.write("lib_ret->obj->" + elem.attrib["name"] + "_container = realloc(lib_ret->obj->"+elem.attrib["name"]+"_container,"+"sizeof("+elem.attrib["name"]+")*("+elem.attrib["name"]+"_agg_count"+" +1));\n")
                else:
                    agg_source.write("lib_ret->obj->" + elem.attrib["name"] + "_container = realloc(lib_ret->obj->"+elem.attrib["name"]+"_container,"+"sizeof("+elem.attrib["name"]+")*("+elem.attrib["name"]+"_agg_count"+" +1));\n")
                agg_source.write("lib_ret->obj->"+elem.attrib["name"] + "_container["+elem.attrib["name"]+"_agg_count"+"] = " + "ft_read_" + elem.attrib["name"] + "(_fd, &lib_ret->obj->" + elem.attrib["name"] + "_container["+elem.attrib["name"]+"_agg_count"+"], "  + "&lib_ret->void_train, &lib_ret->current_void_size, &lib_ret->current_void_count);\n")
                agg_source.write(elem.attrib["name"] + "_agg_count++;\n")
            if "unordered" in elem.attrib: agg_source.write("}\n")

            if "unorderedend" in elem.attrib:
                agg_source.write("}while(0);\n")
        agg_source.write("return lib_ret;\n")
        agg_source.write("}\n")

    #FIXME-not handling double pointers
    def gen_release(self):
        agg_source = open(self.aggregate_source, "a")
        agg_source_h = open(self.aggregate_source_h, "a")
        agg_source_h.write("void release_all_"+self.argparser.args.name+"(void** void_train, uint64_t current_void_count);\n")
        agg_source.write("void release_all_"+self.argparser.args.name+"(void** void_train, uint64_t current_void_count) {\n")
        agg_source.write("for (int i=current_void_count-1;i>=0;--i) {\n")
        agg_source.write("free(void_train[i]);\n}\n")
        agg_source.write("free(void_train);\n")
        agg_source.write("}\n")
        agg_source_h.write('#ifdef __cplusplus\n}\n#endif\n')
        agg_source_h.write("#endif //end of header guard\n\n")

    def gen_return(self):
        agg_source = open(self.aggregate_source, "a")
        agg_source_h = open(self.aggregate_source_h, "a")
        for elem in self.read_elems:
            agg_source.write(elem.attrib["name"] + "* ft_ret_" + elem.attrib["name"] + "(void) {\n")
            agg_source.write("return " + elem.attrib["name"] + "_container"+ ";\n")
            agg_source.write("}\n")
            agg_source_h.write(elem.attrib["name"] + "* ft_ret_" + elem.attrib["name"] + "(void);\n")
        agg_source_h.write('#ifdef __cplusplus\n}\n#endif\n')
        agg_source_h.write("#endif //end of header guard\n\n")

    def read_xml(self):
        if self.argparser.args.xml:
            def_header = open(self.argparser.args.outdir + "/defines.h", "w")
            def_header.write("\n// automatically generated by faultreiber\n")
            def_header.write("// " + self.dnt + "\n")
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

    def gen_struct_header_xml(self):
        struct_source = open(self.struct_source_h, "w")
        struct_source_c = open(get_full_path(self.argparser.args.outdir, "structs.c"), "w")
        struct_source.write(text.autogen_warning)
        struct_source_c.write(text.autogen_warning)
        struct_source.write("// " + self.dnt + "\n")
        struct_source_c.write("// " + self.dnt + "\n")
        struct_source.write("#ifndef FT_STRUCTS_H\n#define FT_STRUCTS_H\n")
        struct_source.write('#ifdef __cplusplus__\nextern "C" {\n#endif\n')
        struct_source_c.write('#include "structs.h"\n')
        struct_source_c.write('#include "stdlib.h"\n')
        struct_source_c.write('#include "stdio.h"\n')
        struct_source.write('#include <unistd.h>\n')
        if self.argparser.args.calloc: struct_source_c.write(text.ft_calloc_def)
        struct_source.write(text.header_inttype)
        struct_source_c.write(text.c_read_leb_u_def + "\n")
        struct_source_c.write(text.c_read_leb_s_def + "\n")
        struct_source_c.write(text.c_read_until_delimiter + "\n")
        if self.argparser.args.calloc: struct_source_c.write(text.c_void_manager.replace("CCC", "ft_calloc").replace("XXX", repr(self.argparser.args.voidtraininitsize)).replace("YYY", repr(self.argparser.args.voidtrainfactor)) + "\n")
        else: struct_source_c.write(text.c_void_manager.replace("CCC", "malloc").replace("XXX", repr(self.argparser.args.voidtraininitsize)).replace("YYY", repr(self.argparser.args.voidtrainfactor)) + "\n")
        struct_source.write("extern void** void_train;\n")
        struct_source.write("extern uint64_t current_void_size;\n")
        struct_source.write("extern uint64_t current_void_count;\n")
        struct_source.write(text.c_read_leb_128_u_sig + "\n")
        struct_source.write(text.c_read_leb_128_s_sig + "\n")
        struct_source.write(text.c_read_until_delimiter_sig + "\n")
        struct_source.write(text.c_void_manager_sig + "\n")
        if self.argparser.args.structsinclude:
            copy(self.argparser.args.structsinclude, self.argparser.args.outdir)
            pos = self.argparser.args.structsinclude.rfind("/")
            sub = self.argparser.args.structsinclude[pos+1:]
            struct_source.write('#include "' + sub + '"\n\n')
        for child in self.def_elems + self.read_elems:
            struct_source.write("typedef struct {\n")
            if not "isaggregate" in child.attrib:
                ref_type = type_resolver(child, self.def_elems + self.read_elems)
                def_node = get_def_node(ref_type, self.def_elems + self.read_elems)
                pointer = str()
                if "count" in child.attrib:
                    if child.attrib["count"] != "1":
                        pointer = "*"
                if def_node:
                    struct_source.write(ref_type + pointer + "* " + child.attrib["name"] + ";\n")
                else:
                    struct_source.write(ref_type + pointer + " " + child.attrib["name"] + ";\n")
            for childer in child:
                ref_type = type_resolver(childer, self.def_elems + self.read_elems)
                def_node = get_def_node(ref_type, self.def_elems + self.read_elems)
                pointer = str()
                if "count" in childer.attrib:
                    if childer.attrib["count"] != "1":
                        pointer = "*"
                if def_node:
                    struct_source.write(ref_type + pointer + "* " + childer.attrib["name"] + ";\n")
                else:
                    struct_source.write(ref_type + pointer + " " + childer.attrib["name"] + ";\n")
            struct_source.write("}" + child.attrib["name"] + ";\n\n")
        struct_source.write('#ifdef __cplusplus__\n}\n#endif\n')
        struct_source.write(text.pragma_endif)
        struct_source.write(text.last_comment)

    def run(self):
        alloc = str()
        if self.argparser.args.calloc: alloc = "ft_calloc"
        elif self.argparser.args.luaalloc: alloc = "ft_lua_newuserdata"
        else: alloc = "malloc"
        self.init()
        self.init_hook()
        self.file_manager()
        self.read_xml()
        self.gen_reader_funcs(alloc)
        self.gen_struct_header_xml()
        if self.argparser.args.luaalloc:
            pass
        else:
            self.gen_void_train(alloc)
        self.gen_void_train(alloc)
        self.gen_aggregate_read()
        if self.argparser.args.luaalloc:
            pass
        else:
            self.gen_release()
        self.gen_release()
        #self.gen_return()

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
