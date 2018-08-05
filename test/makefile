TARGET=autowasm
CC=clang
CC?=clang
CC_FLAGS=-fpic
CC_EXTRA?=
CTAGS_I_PATH?=./
LD_FLAGS=
EXTRA_LD_FLAGS?=
ADD_SANITIZERS_CC= -g -fsanitize=address -fno-omit-frame-pointer
ADD_SANITIZERS_LD= -g -fsanitize=address
MEM_SANITIZERS_CC= -g -fsanitize=memory -fno-omit-frame-pointer
MEM_SANITIZERS_LD= -g -fsanitize=memory
UB_SANITIZERS_CC= -g -fsanitize=undefined -fno-omit-frame-pointer
UB_SANITIZERS_LD= -g -fsanitize=undefined
# BUILD_MODES are=RELEASE(default), DEBUG,ADDSAN,MEMSAN,UBSAN
BUILD_MODE?=RELEASE

ifeq ($(BUILD_MODE), ADDSAN)
ifeq ($(CC), gcc)
$(error This build mode is only useable with clang.)
endif
CC_EXTRA+=$(ADD_SANITIZERS_CC)
EXTRA_LD_FLAGS+=$(ADD_SANITIZERS_LD)
endif

ifeq ($(BUILD_MODE), MEMSAN)
ifeq ($(CC), gcc)
$(error This build mode is only useable with clang.)
endif
CC_EXTRA+=$(MEM_SANITIZERS_CC)
EXTRA_LD_FLAGS+=$(MEM_SANITIZERS_LD)
endif

ifeq ($(BUILD_MODE), UBSAN)
ifeq ($(CC), gcc)
$(error This build mode is only useable with clang.)
endif
CC_EXTRA+=$(UB_SANITIZERS_CC)
EXTRA_LD_FLAGS+=$(UB_SANITIZERS_LD)
endif

SRCS:=$(wildcard *.c)
CC_FLAGS+=$(CC_EXTRA)
LD_FLAGS+=$(EXTRA_LD_FLAGS)

.DEFAULT:all

.PHONY:all clean help ASM SO TAGS

all:$(TARGET)

everything:$(TARGET) A ASM SO $(TARGET)-static $(TARGET)-dbg TAGS

depend:.depend

.depend:$(SRCS)
	rm -rf .depend
	$(CC) -MM $(CC_FLAGS) $^ > ./.depend

-include ./.depend

.c.o:
	$(CC) $(CC_FLAGS) -c $< -o $@

%.odbg:%.c
	$(CC) $(CC_FLAGS) -g -c $< -o $@

$(TARGET): $(TARGET).o read.o structs.o aggregate.o
	$(CC) $^ $(LD_FLAGS) -o $@

$(TARGET)-static: $(TARGET).o read.o structs.o aggregate.o
	$(CC) $^ $(LD_FLAGS) -static -o $@

$(TARGET)-dbg: $(TARGET).odbg read.odbg structs.odbg aggregate.odbg
	$(CC) $^ $(LD_FLAGS) -g -o $@

ASM:$(TARGET).asm

SO:$(TARGET).so

A:$(TARGET).a

TAGS:tags

tags:$(SRCS)
	$(shell $(CC) -c -I $(CTAGS_I_PATH) -M $(SRCS)|\
		sed -e 's/[\\ ]/\n/g'|sed -e '/^$$/d' -e '/\.o:[ \t]*$$/d'|\
		ctags -L - --c++-kinds=+p --fields=+iaS --extra=+q)

$(TARGET).asm: $(TARGET).o read.o structs.o aggregate.o
	objdump -r -d -M intel -S $(TARGET).o > $(TARGET).asm

$(TARGET).so: $(TARGET).o read.o structs.o aggregate.o
	$(CC) $^ $(LD_FLAGS) -shared -o $@

$(TARGET).a: $(TARGET).o read.o structs.o aggregate.o
	ar rcs $(TARGET).a $(TARGET).o

clean:
	rm -f *.o *.odbg *~ $(TARGET) $(TARGET).so $(TARGET).asm $(TARGET)-static $(TARGET)-dbg $(TARGET).a

deepclean:
	rm -f *.o *.odbg *~ $(TARGET) $(TARGET).so $(TARGET).asm tags $(TARGET)-static $(TARGET)-dbg $(TARGET).a
	rm .depend

help:
	@echo "--all is the default target, runs $(TARGET) target"
	@echo "--everything will build everything"
	@echo "--SO will generate the so"
	@echo "--ASM will generate assembly files"
	@echo "--TAGS will generate tags file"
	@echo "--$(TARGET) builds the dynamically-linked executable"
	@echo "--$(TARGET)-dbg will generate the debug build. BUILD_MODE should be set to DEBUG to work"
	@echo "--$(TARGET)-static will statically link the executable to the libraries"
	@echo "--A will build the static library"
	@echo "--TAGS will build the tags file"
	@echo "--clean"
	@echo "--deepclean will clean almost everything"
