
#ifndef WASM_H
#define WASM_H
#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef uint8_t varint1;
typedef uint8_t varint7;
typedef uint32_t varint32;
typedef int8_t varuint1;
typedef int8_t varuint7;
typedef int32_t varuint32;

  enum value_type_t {f64_vt = -4, f32_vt, i64_vt, i32_vt};
  enum external_kind_t {Function, Table, Memory, Global};
  enum type_ctor_t {i32_ctor = -1, i64_ctor = -2, f32_ctor = -3, f64_ctor = -4, anyfunc_ctor = -16, func_ctor = -32, block_type_ctor = -64};

#ifdef __cplusplus
}
#endif // end of extern c
#endif // end of header guard
/**********************************************************************************************************************/
/*last line intentionally left blank.*/

