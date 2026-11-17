#ifndef WOODY_H
# define WOODY_H

# include <elf.h>
# include <errno.h>
# include <fcntl.h>
# include <inttypes.h>
# include <limits.h>
# include <stddef.h>
# include <stdint.h>
# include <stdio.h>
# include <stdlib.h>
# include <string.h>
# include <sys/mman.h>
# include <sys/stat.h>
# include <sys/syscall.h>
# include <sys/types.h>
# include <unistd.h>

# define WOODY_OUTPUT_NAME "woody"
# define WOODY_PAGE_SIZE 4096ULL
# define WOODY_KEY_SIZE 16U
# define WOODY_NONCE_SIZE 8U
# define WOODY_SEGMENT_DESC_SIZE 56U

int     woody_load_file(const char *path, unsigned char **buffer, size_t *size,
            struct stat *identity);
int     woody_write_file_atomic(const char *path, const unsigned char *buffer,
            size_t size, const struct stat *input_identity);
int     woody_random_bytes(unsigned char *buffer, size_t size);
int     woody_get_page_size(uint64_t *page_size);
void    woody_xtea_ctr(unsigned char *buffer, size_t size,
            const uint32_t key[4], uint64_t nonce);
void    woody_xtea_ctr_asm(unsigned char *buffer, size_t size,
            const uint32_t key[4], uint64_t nonce);
uint32_t woody_crc32(const unsigned char *buffer, size_t size);
int     woody_pack_elf(const unsigned char *input, size_t input_size,
            unsigned char **output, size_t *output_size,
            const unsigned char key_bytes[WOODY_KEY_SIZE], uint64_t nonce,
            int compress_payloads);
int     woody_lzss_compress(const unsigned char *input, size_t input_size,
            unsigned char **output, size_t *output_size);
int     woody_lzss_decompress(const unsigned char *input, size_t input_size,
            unsigned char *output, size_t output_size);
int     woody_pack_elf32(const unsigned char *input, size_t input_size,
            unsigned char **output, size_t *output_size,
            const unsigned char key_bytes[WOODY_KEY_SIZE], uint64_t nonce);
void    woody_print_key(const unsigned char key[WOODY_KEY_SIZE], uint64_t nonce);

#endif
