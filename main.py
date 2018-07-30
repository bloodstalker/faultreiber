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
        return "int8_t"
    elif type_str == "schar":
        return "schar_t"
    elif type_str == "string":
        return "char*"
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

def get_elem_count(elem, elems):
    if "count" in elem.attrib:
        try:
            if str(int(elem.attrib["count"])) == elem.attrib["count"]:
                return int(elem.attrib["count"])
        except ValueError:
            return -1
    else:
        return 1

def get_elem_size(elem, elems):
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
        parser.add_argument("--dbg", action="store_true", help="debug", default=False)
        parser.add_argument("--datetime", action="store_true", help="print date and time in autogen files", default=False)
        parser.add_argument("--inline", action="store_true", help="inlines reader funcs", default=False)
        parser.add_argument("--static", action="store_true", help="statics reader funcs", default=False)
        parser.add_argument("--verbose", action="store_true", help="verbose", default=False)
        # TODO
        parser.add_argument("--forcenullterm", action="store_true", help="terminate all strings with null even if they are not null-terminated", default=False)
        # TODO
        parser.add_argument("--buffersize", type=int, help="the size of the buffer for special reads(e.g. strings)", default=100)
        # TODO
        parser.add_argument("--buffgrowfactor", type=float, help="main target name", default=1.6)
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
        self.mem_size = {}

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

    def dump_mem_dict(self):
        for key, value in self.mem_size.items():
            print(key + ".." + value)

    def gen_reader_funcs(self):
        temp_dec_list = []
        read_source = open(self.argparser.args.outdir + "/read.c", "w")
        read_source.write("\n// automatically generated by faultrieber\n")
        read_source.write("// " + self.dnt + "\n\n")
        read_source.write(text.header_list)
        read_source.write('#include "./structs.h"\n\n')
        inline = "inline " if self.argparser.args.inline else ""
        static = "static " if self.argparser.args.static else ""
        for elem in self.def_elems + self.read_elems:
            dummy_list = []
            dummy_string = str()
            pointer = str()
            access = "."
            dummy_static = str()
            if "isaggregate" in elem.attrib:
                #pointer = "*"
                pointer = ""
                access = "->"
                dummy_static = ""
            if "isaggregate" in elem.attrib:
                dummy_string += ", " + elem.attrib["name"] + "*"  + " dummy_" + elem.attrib["name"]
                read_source.write(static + inline + text.c_read_elem_sig.replace("YYY", elem.attrib["name"]).replace("XXX", elem.attrib["name"]+pointer))
                count = get_elem_count(elem, self.read_elems+self.def_elems)
                if count == 1:
                    for child in elem:
                        child_count = get_elem_count(child, self.def_elems + self.read_elems)
                        ref_node_name = type_resolver(child, self.def_elems)
                        ref_node = get_def_node(ref_node_name, self.def_elems)
                        size = get_elem_size(child, self.def_elems + self.read_elems)
                        read_size_replacement = str()
                        if size > 0:
                            read_size_replacement = str(size)
                        if size == -1:
                            ref_size = "dummy->" + get_node_name(child.attrib["size"][6:], elem)

                        if ref_node:
                            ref_node_name = pointer_remover(ref_node.attrib["name"])
                            if child_count == 1:
                                for_read = text.c_read_elem_sig_2.replace("XXX", ref_node_name).replace("YYY", "dummy->" + child.attrib["name"]) + ";\n"
                                read_source.write(for_read)
                            elif child_count > 1:
                                for_read = text.c_read_elem_sig_2.replace("XXX", ref_node_name).replace("YYY", "dummy->" + child.attrib["name"] + "[i]") + ";\n"
                                read_source.write(for_read)
                            else: # child_count == -1
                                count_name_str = child.attrib["count"][6:]
                                for_read = text.c_read_elem_sig_2.replace("XXX", ref_node_name).replace("YYY", "dummy->" + child.attrib["name"] + "[i]") + ";\n"
                                read_source.write(text.simple_loop.replace("YYY", for_read).replace("XXX", "dummy->" + get_node_name(count_name_str, elem)))
                        else:
                            for_read = str()
                            if child_count == 1: array_subscript = ""
                            elif child_count > 1: array_subscript = "[i]"
                            else: array_subscript = "[i]"
                            if "size" in child.attrib:
                                if "encoding" in child.attrib:
                                    for_read = "dummy->" + child.attrib["name"] + array_subscript + "=" + get_encoding_read(child.attrib["encoding"])
                                else:
                                    for_read = text.c_read_gen_2.replace("XXX", "dummy" + "->"+ child.attrib["name"] + array_subscript).replace("YYY", ref_size)
                            else:
                                if "encoding" in child.attrib:
                                    for_read = "dummy->" + child.attrib["name"] + array_subscript + " = " + get_encoding_read(child.attrib["encoding"])
                                else:
                                    for_read = text.c_read_gen.replace("XXX", "dummy" + "->" + child.attrib["name"] + array_subscript).replace("YYY", ref_node_name)
                            if child_count == 1:
                                read_source.write(for_read)
                            elif child_count > 1:
                                read_source.write(text.simple_loop.replace("YYY", for_read).replace("XXX", str(child_count)))
                            else: # child_count = -1
                                count_name_str = child.attrib["count"][6:]
                                read_source.write(text.simple_loop.replace("YYY", for_read).replace("XXX", "dummy->" + get_node_name(count_name_str, elem)))
                else:
                    pass
            # if not aggregate
            # if its an aggregate type there is only a single element in the
            # read funtion so we dont really need to worry about multiple
            # instances with the same name
            else:
                read_source.write(static + inline + text.c_read_elem_sig.replace("YYY", elem.attrib["name"]).replace("XXX", elem.attrib["name"]+pointer))
                read_source.write(text.c_read_gen.replace("XXX", "dummy->" + elem.attrib["name"]).replace("YYY", type_resolver(elem, self.def_elems)))
            #read_source.write(text.c_function_return_type)
            read_source.write(text.c_function_close + "\n")

    def gen_void_train(self):
        void_source = open(self.argparser.args.outdir + "/void.h", "w")
        void_source.write("\n// automatically generated by faultreiber\n")
        void_source.write("// " + self.dnt + "\n")
        void_source.write('#include "./structs.h"\n')
        void_source.write('#include "./read.c"\n')
        void_source.write("#include <stdlib.h>\n")
        void_source.write("void** void_train(void) {\n")
        count_int = int()
        count_void = int()
        read_count = len(self.read_elems)
        for elem in self.read_elems + self.def_elems:
            if "isaggregate" in elem.attrib:
                for child in elem:
                    count = get_elem_count(child, self.def_elems + self.read_elems)
                    size = get_elem_size(child, self.def_elems + self.read_elems)
                    type_width = get_type_width(child)
                    #print(child.tag + ":" + str(type_width))
                    if "count" in child.attrib: pass
                    if "size" in child.attrib: pass
                    if count > 0: count_int+=count*type_width
                    if count < 0: count_void+=1
                    if size > 0: count_int+=size
                    if size < 0: count_void+=1
                self.mem_size[elem.attrib["name"]] = (str(count_int)+"+" if count_int > 0 else "") + (str(count_void)+"*"+"sizeof(void*)") if count_void > 0 else ""
                count_int = 0
                count_void = 0
            else:
                if "size" in elem.attrib:
                    count = get_elem_count(elem, self.def_elems + self.read_elems)
                    if count > 0: count_int+= count
                    else: count_void+=1
                if "count" in elem.attrib:
                    size = get_elem_size(elem, self.def_elems + self.read_elems)
                    if size > 0: count_int+=size
                    else: count_void+=1
            #void_source.write("void* ptr = malloc(sizeof(void*));\n")
                self.mem_size[elem.attrib["name"]] = (str(count_int)+"+" if count_int > 0 else "") + (str(count_void)+"*"+"sizeof(void*)") if count_void > 0 else ""
                count_int = 0
                count_void = 0
        void_source.write("}")

    def gen_aggregate_read(self):
        agg_source = open(self.argparser.args.outdir + "/aggregate.h", "w")
        agg_source.write("\n// automatically generated by faultreiber\n")
        agg_source.write("// " + self.dnt + "\n")
        agg_source.write('#include "./structs.h"\n')
        agg_source.write('#include "./read.c"\n')
        agg_source.write("void read_aggr(void) {\n")
        for elem in self.read_elems:
            agg_source.write("ft_read_" + elem.attrib["name"] + "(_fd, );\n")
        agg_source.write("}")

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
        struct_source = open(get_full_path(self.argparser.args.outdir, "structs.h"), "w")
        struct_source_c = open(get_full_path(self.argparser.args.outdir, "structs.c"), "w")
        struct_source_c.write('#include "structs.h"')
        struct_source.write(text.pre_header_guard)
        struct_source.write(text.autogen_warning)
        if self.argparser.args.datetime: struct_source.write("// " + self.dnt + "\n")
        struct_source.write(text.header_guard_begin.replace("XXX", "structs".upper()))
        struct_source.write(text.header_inttype)
        struct_source.write(text.c_read_leb_u_def + "\n")
        struct_source.write(text.c_read_leb_s_def + "\n")
        struct_source.write(text.c_read_leb_macro_defs + "\n")
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
        struct_source.write(text.pragma_endif)
        #struct_source.write(text.last_comment)

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
        #self.gen_struct_header()
        self.read_xml()
        self.gen_reader_funcs()
        self.gen_struct_header_xml()
        #self.dump_def_elems()
        #self.dump_read_elems()
        self.gen_void_train()
        self.gen_aggregate_read()
        self.dump_mem_dict()

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
