
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "./structs.h"
#include "./read.h"
#include "./aggregate.h"

#pragma weak main
int main (int argc, char** argv) {
  int wasm = open("./test.wasm", O_RDONLY);
  read_aggr(wasm);

  printf("magic_number:%x\n", magic_number_container->magic_number);
  printf("version:%x\n", version_container->version);

  printf("type section id:%d\n", W_Type_Section_container->id);
  printf("type section payloadlength:%d\n", W_Type_Section_container->payloadlength);
  printf("type_section entry count:%d\n", W_Type_Section_container->count);
  for (int i=0; i < W_Type_Section_container->count; ++i) {
    printf("param_count:%d\n",W_Type_Section_container->entries[i]->param_count);
    for (int j = 0; j < W_Type_Section_container->entries[i]->param_count; ++j)
      printf("param_types:%d\n",W_Type_Section_container->entries[i]->param_types[j]);
    printf("return_count:%d\n", W_Type_Section_container->entries[i]->return_count);
    for (int j = 0; j < W_Type_Section_container->entries[i]->return_count; ++j)
      printf("param_types:%d\n",W_Type_Section_container->entries[i]->return_types[j]);
  }
  printf("import_section_id:%d\n", W_Import_Section_container->id);
  printf("import_section_payloadlength:%d\n", W_Import_Section_container->payloadlength);
  printf("import_section_count:%d\n", W_Import_Section_container->count);
  for(int i = 0; i < W_Import_Section_container->count; ++i) {
    printf("module_length:%d\n", W_Import_Section_container->entries[i]->module_length);
    printf("module_str:%s\n", W_Import_Section_container->entries[i]->module_str);
    printf("field_length:%d\n", W_Import_Section_container->entries[i]->field_len);
    printf("field_str:%s\n", W_Import_Section_container->entries[i]->field_str);
    printf("kind:%d\n", W_Import_Section_container->entries[i]->kind);
    if (W_Import_Section_container->entries[i]->kind == 0)
      printf("type:%d\n", W_Import_Section_container->entries[i]->kind);
    printf("\n");
  }
  printf("function_section_id:%d\n", W_Function_Section_container->id);
  printf("function_section_payloadlength:%d\n", W_Function_Section_container->payloadlength);
  printf("function_section_count:%d\n", W_Function_Section_container->count);
  for (int i = 0; i < W_Function_Section_container->count; ++i)
    printf("type:%d\n", W_Function_Section_container->types[i]);

  printf("table_section_id:%d\n", W_Table_Section_container->id);
  printf("table_section_payloadlength:%d\n", W_Table_Section_container->payloadlength);
  printf("table_section_count:%d\n", W_Table_Section_container->count);
  for (int i = 0; i < W_Table_Section_container->count; ++i) {
    printf("element_type:%d\n", W_Table_Section_container->entries[i]->element_type);
    printf("rl_flags:%d\n", W_Table_Section_container->entries[i]->resizable_limit->flags);
    printf("rl_initial:%d\n", W_Table_Section_container->entries[i]->resizable_limit->initial);
    printf("rl_maximum:%d\n", W_Table_Section_container->entries[i]->resizable_limit->maximum);
  }

  printf("memory_section_id:%d\n", W_Memory_Section_container->id);
  printf("memory_section_payload_length:%d\n", W_Memory_Section_container->payloadlength);
  printf("rl_flags:%d\n", W_Memory_Section_container->entries->resizable_limit->flags);
  printf("rl_initial:%d\n", W_Memory_Section_container->entries->resizable_limit->initial);
  printf("rl_maximum:%d\n", W_Memory_Section_container->entries->resizable_limit->maximum);

  if (W_Global_Section_container == NULL) printf("global section doesnt exist.\n");

  printf("export_section_id:%d\n", W_Export_Section_container->id);
  printf("export_section_payloadlength:%d\n", W_Export_Section_container->payloadlength);
  printf("entry count:%d\n", W_Export_Section_container->count);

  for (int i = 0; i < W_Export_Section_container->count; ++i) {
    printf("field_len:%d\n", W_Export_Section_container->entries[i]->field_len);
    printf("field_str:%s\n", W_Export_Section_container->entries[i]->field_str);
    printf("kind:%d\n", W_Export_Section_container->entries[i]->kind);
    printf("index:%d\n", W_Export_Section_container->entries[i]->index);
  }

  release_all();
  return 0;
}
