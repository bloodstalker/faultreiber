
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
  malloc_all();
  read_aggr(wasm);
  magic_number* mn = ft_ret_magic_number();
  version* v = ft_ret_version();
  W_Type_Section* ts = ft_ret_W_Type_Section();
  printf("magic_number:%x\n", mn->magic_number);
  printf("version:%d\n", v->version);
  printf("type section id:%d\n", ts->id);
  printf("type section payloadlength:%d\n", ts->payloadlength);
  printf("type_section entry count:%d\n", ts->count);
  for (int i=0; i < 7; ++i) {
    //printf("param_count:%d\n",ts->entries[i]->param_count);
    //printf("param_count:%d\n",ts->entries[i]);
  }

#if 0
  uint64_t test_u = 0U;
  int64_t test_s = 0;
  unsigned char test_byte;
  unsigned char byte;
  uint32_t word;
  uint32_t counter = 0U;

  read(wasm, &word, 8);
  printf("test_byte:%08x\n", word);

  lseek(wasm, 9, SEEK_SET);
  read(wasm, &word, 8);
  printf("test_byte:%08x\n", word);

  lseek(wasm, 9, SEEK_SET);
  test_u = read_leb_128_u(wasm, 5);
  printf("read u res is: %lu.\n", test_u);
  lseek(wasm, 0, SEEK_SET);
  while(read(wasm, &word, sizeof(uint32_t))) {
    printf("%d:%02x\t", counter, word);
    counter++;
  }
  printf("\n");
#endif
  return 0;
}
