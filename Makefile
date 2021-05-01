# Copyright (c) 2014-2018 Ristretto Developers, Cryptography Research, Inc.
# Released under the MIT License.  See LICENSE.txt for license information.

UNAME := $(shell uname)
MACHINE := $(shell uname -m)

# Subdirectories for objects etc.
BUILD_OBJ  = build/obj
BUILD_LIB  = build/lib
BUILD_IBIN = build/obj/bin

# TODO: fix builds for non-x86_64 architectures
ARCH ?= $(MACHINE)

ifeq ($(UNAME),Darwin)
CC ?= clang
else
CC ?= gcc
endif

LD   = $(CC)
AR  ?= ar
ASM ?= $(CC)

WARNFLAGS = -pedantic -Wall -Wextra -Werror -Wunreachable-code \
	 -Wmissing-declarations -Wunused-function -Wno-overlength-strings -Wno-unused-result $(EXWARN)

INCFLAGS  = -Iinclude -Isrc -Isrc/arch/$(ARCH)
LANGFLAGS = -std=c11 -fno-strict-aliasing
GENFLAGS  = -ffunction-sections -fdata-sections -fomit-frame-pointer -fPIC -fopenmp
OFLAGS   ?= -O2

MACOSX_VERSION_MIN ?= 10.9
ifeq ($(UNAME),Darwin)
GENFLAGS += -mmacosx-version-min=$(MACOSX_VERSION_MIN)
endif

ARCHFLAGS ?= -march=native

ifeq ($(CC),clang)
WARNFLAGS_C += -Wgcc-compat
endif

ARCHFLAGS += $(XARCHFLAGS)
CFLAGS     = $(LANGFLAGS) $(WARNFLAGS) $(WARNFLAGS_C) $(INCFLAGS) $(OFLAGS) $(ARCHFLAGS) $(GENFLAGS) $(XCFLAGS)
LDFLAGS    = $(XLDFLAGS) -lssl -lcrypto -fopenmp
ASFLAGS    = $(ARCHFLAGS) $(XASFLAGS)

.PHONY: clean test all lib
.PRECIOUS: src/%.c src/*/%.c include/%.h include/*/%.h $(BUILD_IBIN)/%

HEADERS= Makefile $(BUILD_OBJ)/timestamp

# components needed by all targets
COMPONENTS = $(BUILD_OBJ)/bool.o \
             $(BUILD_OBJ)/bzero.o \
             $(BUILD_OBJ)/f_impl.o \
             $(BUILD_OBJ)/f_arithmetic.o \
             $(BUILD_OBJ)/ristretto.o \
             $(BUILD_OBJ)/scalar.o

# components needed by libristretto255.so
LIBCOMPONENTS = $(COMPONENTS) $(BUILD_OBJ)/elligator.o $(BUILD_OBJ)/ristretto_tables.o

# components needed by libristretto_elgamal
RECOMPONENTS = $(LIBCOMPONENTS) $(BUILD_OBJ)/ristretto_elgamal_utils.o \
							$(BUILD_OBJ)/encode_single_message.o \
							$(BUILD_OBJ)/decode_single_message.o \
							$(BUILD_OBJ)/encode_single_message_hintless_hashonly.o \
							$(BUILD_OBJ)/decode_single_message_hintless_hashonly.o \
							$(BUILD_OBJ)/encode_file.o \
							$(BUILD_OBJ)/decode_file.o \
							$(BUILD_OBJ)/elgamal.o \
							$(BUILD_OBJ)/fastexp.o

# components needed by the ristretto_gen_tables binary
GENCOMPONENTS = $(COMPONENTS) $(BUILD_OBJ)/ristretto_gen_tables.o

all: lib elligator_test utils_test hintless_test file_test elgamal_test elgamal_gen create_dummy_ciphertext elgamal_bench_offline

# Create all the build subdirectories
$(BUILD_OBJ)/timestamp:
	mkdir -p $(BUILD_OBJ) $(BUILD_LIB) $(BUILD_IBIN)
	touch $@

$(BUILD_OBJ)/f_impl.o: src/arch/$(ARCH)/f_impl.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD_IBIN)/ristretto_gen_tables: $(GENCOMPONENTS)
	$(LD) $(LDFLAGS) -o $@ $^

src/ristretto_tables.c: $(BUILD_IBIN)/ristretto_gen_tables
	./$< > $@ || (rm $@; exit 1)

# The libristretto255 library
lib: $(BUILD_LIB)/libristretto255.so $(BUILD_LIB)/libristretto255.a

$(BUILD_LIB)/libristretto255.so: $(BUILD_LIB)/libristretto255.so.1
	ln -sf `basename $^` $@

$(BUILD_LIB)/libristretto255.so.1: $(LIBCOMPONENTS)
	rm -f $@
ifeq ($(UNAME),Darwin)
	libtool -macosx_version_min $(MACOSX_VERSION_MIN) -dynamic -dead_strip -lc -x -o $@ \
		  $(LIBCOMPONENTS)
else ifeq ($(UNAME),SunOS)
	$(LD) $(LDFLAGS) -shared -Wl,-soname,`basename $@` -o $@ $(LIBCOMPONENTS)
	strip --discard-all $@
else
	$(LD) $(LDFLAGS) -shared -Wl,-soname,`basename $@` -Wl,--gc-sections -o $@ $(LIBCOMPONENTS)
	strip --discard-all $@
endif

$(BUILD_LIB)/libristretto255.a: $(RECOMPONENTS)
	$(AR) rcs $@ $(RECOMPONENTS)

$(BUILD_OBJ)/%.o: src/%.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $@ $<

elligator_test: $(RECOMPONENTS) $(BUILD_OBJ)/elligator_test.o
	$(LD) -o $@ $^ $(LDFLAGS)

utils_test: $(RECOMPONENTS) $(BUILD_OBJ)/ristretto_elgamal_utils_test.o
	$(LD) -o $@ $^ $(LDFLAGS)

hintless_test: $(RECOMPONENTS) $(BUILD_OBJ)/hintless_test.o
	$(LD) -o $@ $^ $(LDFLAGS)

file_test: $(RECOMPONENTS) $(BUILD_OBJ)/file_test.o
	$(LD) -o $@ $^ $(LDFLAGS)

elgamal_gen: $(RECOMPONENTS) $(BUILD_OBJ)/elgamal_gen.o
	$(LD) -o $@ $^ $(LDFLAGS)

elgamal_test: $(RECOMPONENTS) $(BUILD_OBJ)/elgamal_test.o
	$(LD) -o $@ $^ $(LDFLAGS)

create_dummy_ciphertext: $(RECOMPONENTS) $(BUILD_OBJ)/create_dummy_ciphertext.o
	$(LD) -o $@ $^ $(LDFLAGS)

elgamal_bench_offline: $(RECOMPONENTS) $(BUILD_OBJ)/elgamal_bench_offline.o
	$(LD) -o $@ $^ $(LDFLAGS)

# Test suite: requires Rust is installed
test: $(BUILD_LIB)/libristretto255.a
	cd tests && cargo test --all --lib

clean:
	rm -fr build tests/target
