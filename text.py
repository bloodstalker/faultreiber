# _*_ coding=utf-8 _*_

class text():
    header_list = """#include <fcntl.h>\n
        #include <inttypes.h>\n
        #include <stdio.h>\n
        #include <stdlib.h>\n
        #include <unistd.h>\n"""
    header_inttype = "#include <inttypes.h>\n"
    main_sig = 'int main(int argc, char** argv)'
    pragma_weak_main = '#pragma weak main'
    pre_header_guard = "\n// first line intentionally left blank\n"
    header_guard_begin = "#ifndef _AUTO_XXX_H\n#define _AUTO_XXX_H\n"
    pragma_endif = "#endif\n"
    autogen_warning = "// this file has been automatically generated by faultreiber\n"
    last_comment = "// last line intentionally left blank\n\n"
    read_func_sig = "int read_structured_file(char* path)"
