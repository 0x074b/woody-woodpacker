NAME        := woody_woodpacker
CC          ?= cc
PYTHON      ?= python3
OBJCOPY     ?= objcopy
AS          ?= as
CFLAGS      := -Wall -Wextra -Werror -O2 -Iinclude -fno-stack-protector
ASFLAGS     :=
LDFLAGS     :=

SRC_DIR     := src
OBJ_DIR     := build
STUB_DIR    := stub
TOOLS_DIR   := tools

C_SOURCES   := $(SRC_DIR)/main.c \
               $(SRC_DIR)/io.c \
               $(SRC_DIR)/random.c \
               $(SRC_DIR)/integrity.c \
               $(SRC_DIR)/lzss.c \
               $(SRC_DIR)/elf32_packer.c \
               $(SRC_DIR)/elf_packer.c
C_OBJECTS   := $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(C_SOURCES))
ASM_SOURCES := $(SRC_DIR)/crypto_xtea_asm.S
ASM_OBJECTS := $(patsubst $(SRC_DIR)/%.S,$(OBJ_DIR)/%.o,$(ASM_SOURCES))
STUB_OBJECT := $(OBJ_DIR)/woody_stub.o
STUB_BINARY := $(OBJ_DIR)/woody_stub.bin
STUB_HEADER := include/woody_stub_blob.h
STUB32_OBJECT := $(OBJ_DIR)/woody_stub32.o
STUB32_BINARY := $(OBJ_DIR)/woody_stub32.bin
STUB32_HEADER := include/woody_stub32_blob.h
EMBED_TOOL  := $(OBJ_DIR)/embed_stub

all: $(NAME)

$(NAME): $(C_OBJECTS) $(ASM_OBJECTS)
	$(CC) $(CFLAGS) $(LDFLAGS) $(C_OBJECTS) $(ASM_OBJECTS) -o $@

$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c include/woody.h $(STUB_HEADER) $(STUB32_HEADER) | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(STUB_OBJECT): $(STUB_DIR)/woody_stub.S | $(OBJ_DIR)
	$(CC) -c $(ASFLAGS) $< -o $@

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.S | $(OBJ_DIR)
	$(CC) -c $(ASFLAGS) $< -o $@

$(EMBED_TOOL): $(TOOLS_DIR)/embed_stub.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -std=c11 $< -o $@

$(STUB_HEADER): $(STUB_OBJECT) $(EMBED_TOOL)
	$(EMBED_TOOL) $(STUB_OBJECT) $(STUB_BINARY) $@

$(STUB32_OBJECT): $(STUB_DIR)/woody_stub32.S | $(OBJ_DIR)
	$(AS) --32 -o $@ $<

$(STUB32_HEADER): $(STUB32_OBJECT) $(EMBED_TOOL)
	$(EMBED_TOOL) $(STUB32_OBJECT) $(STUB32_BINARY) $@

clean:
	rm -rf $(OBJ_DIR)

fclean: clean
	rm -f $(NAME) woody

re:
	$(MAKE) fclean
	$(MAKE) all

test: $(NAME)
	$(CC) $(CFLAGS) tests/crypto_equivalence.c src/crypto_xtea.c $(OBJ_DIR)/crypto_xtea_asm.o -o $(OBJ_DIR)/crypto_equivalence
	./$(OBJ_DIR)/crypto_equivalence
	$(CC) $(CFLAGS) tests/lzss_equivalence.c src/lzss.c $(STUB_OBJECT) -o $(OBJ_DIR)/lzss_equivalence
	./$(OBJ_DIR)/lzss_equivalence
	$(PYTHON) tests/check_elf32_mprotect.py
	$(PYTHON) tests/check_elf32_xtea_layout.py
	@if $(CC) -m32 -ffreestanding -fno-pie -fno-stack-protector -fno-builtin -Wall -Wextra -Werror -O2 -c tests/elf32_xtea_equivalence.c -o $(OBJ_DIR)/elf32_xtea_equivalence.o >/dev/null 2>&1 \
		&& $(AS) --32 -o $(OBJ_DIR)/elf32_xtea_start.o tests/elf32_xtea_start.S \
		&& ld -m elf_i386 -e _start -o $(OBJ_DIR)/elf32_xtea_equivalence $(OBJ_DIR)/elf32_xtea_start.o $(OBJ_DIR)/elf32_xtea_equivalence.o $(STUB32_OBJECT); then \
		if ./$(OBJ_DIR)/elf32_xtea_equivalence >/dev/null 2>&1; then \
			./$(OBJ_DIR)/elf32_xtea_equivalence; \
		else \
			rc=$$?; if [ $$rc -eq 126 ] || [ $$rc -eq 127 ]; then echo "ELF32 XTEA runtime test skipped (IA32 execution unavailable)"; else ./$(OBJ_DIR)/elf32_xtea_equivalence; exit $$rc; fi; \
		fi; \
	else \
		echo "ELF32 XTEA runtime test skipped (32-bit code generation/linker unavailable)"; \
	fi
	$(AS) --32 -o $(OBJ_DIR)/sample32.o tests/sample32.S
	ld -m elf_i386 -o $(OBJ_DIR)/sample32 $(OBJ_DIR)/sample32.o
	./tests/smoke.sh

.PHONY: all clean fclean re test