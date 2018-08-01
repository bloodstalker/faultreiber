
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "./read.c"
#include "./aggregate.h"

uint64_t read_leb128_u(int _fd, int max_size) {
  uint8_t read_bytes = 0U;
  uint8_t byte = 0;
  uint64_t result = 0U;
  uint32_t shift = 0U;
  do {
    read(_fd, &byte, 1);read_bytes++;read_bytes++;
    result |= (byte & 0x7f) << shift;
    shift += 7;
  } while(((byte & 0x80) != 0) && (read_bytes < max_size));
  return result;
}

int64_t read_leb128_s(int _fd, int max_size) {
  uint8_t byte;
  uint8_t read_bytes = 0U;
  uint8_t last_byte;
  int64_t result = 0;
  uint32_t shift = 0U;
  read(_fd, &byte, 1);
  do {
    read(_fd, &byte, 1);read_bytes++;
    result |= (byte & 0x7f) << shift;
    last_byte = byte;
    shift += 7;
  } while(((byte & 0x80) != 0) && read_bytes < max_size);
  if ((last_byte & 0x40) != 0) result |= -(1 << shift);
  return result;
}

#pragma weak main
int main (int argc, char** argv) {
  int wasm = open("./test.wasm", O_RDONLY);
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
  test_u = READ_VAR_UINT_32(wasm);
  printf("read u res is: %lu.\n", test_u);
  lseek(wasm, 0, SEEK_SET);
  while(read(wasm, &word, sizeof(uint32_t))) {
    printf("%d:%02x\t", counter, word);
    counter++;
  }
  printf("\n");
  return 0;
}
