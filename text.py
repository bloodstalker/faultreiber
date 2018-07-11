# _*_ coding=utf-8 _*_

class text():
    header_list = """#include <fcntl.h>\n#include <inttypes.h>\n#include <stdio.h>\n#include <stdlib.h>\n#include <unistd.h>\n#include <string.h>\n"""
    header_inttype = "#include <inttypes.h>\n"
    main_sig = 'int main(int argc, char** argv)'
    pragma_weak_main = '#pragma weak main'
    pre_header_guard = "\n// first line intentionally left blank\n"
    header_guard_begin = "#ifndef _AUTO_XXX_H\n#define _AUTO_XXX_H\n"
    pragma_endif = "#endif\n"
    autogen_warning = "// this file has been automatically generated by faultreiber\n"
    last_comment = "// last line intentionally left blank\n\n"
    read_func_sig = "int read_structured_file(char* path)"
    c_read_elem_sig = "XXX ft_read_YYY(int _fd) {\n"
    c_read_elem_sig_1 = "ft_read_XXX(_fd)"
    c_open_file = "int ft_read_file = open(_ft_file_path, RDONLY);\n"
    c_function_close = "}\n"
    c_function_dummy_dec = "XXX dummy;\n"
    c_function_return_type = "return dummy;\n"
    c_read_def_1 = "uint8_t XXX;\n"
    c_read_def_2 = "uint16_t XXX;\n"
    c_read_def_4 = "uint32_t XXX;\n"
    c_read_def_8 = "uint64_t XXX;\n"
    c_read_1 = "read(_fd, &XXX, sizeof(uint8_t));\n"
    c_read_2 = "read(_fd, &XXX, sizeof(uint16_t));\n"
    c_read_4 = "read(_fd, &XXX, sizeof(uint32_t));\n"
    c_read_8 = "read(_fd, &XXX, sizeof(uint64_t));\n"
    c_read_gen = "read(_fd, &XXX, sizeof(YYY));\n"
    c_assign_struct = "XXX.YYY = ZZZ;\n"
