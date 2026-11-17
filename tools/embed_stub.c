#define _POSIX_C_SOURCE 200809L

#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

typedef struct s_buffer
{
    char    *data;
    size_t  length;
    size_t  capacity;
}   t_buffer;

typedef struct s_stub_symbols
{
    uint64_t    start;
    uint64_t    end;
    uint64_t    segment_count;
    uint64_t    segment_table;
    uint64_t    key;
    uint64_t    jump_disp;
    const char  *array_name;
    const char  *guard_name;
    const char  *size_macro;
    const char  *count_macro;
    const char  *table_macro;
    const char  *key_macro;
    const char  *jump_macro;
    unsigned    count_width;
    unsigned    elf_class;
}   t_stub_symbols;

static int range_is_valid(size_t total, uint64_t offset, uint64_t length)
{
    if (offset > (uint64_t)total)
        return (0);
    if (length > (uint64_t)total - offset)
        return (0);
    return (1);
}

static void report_error(const char *message)
{
    fprintf(stderr, "embed_stub: %s\n", message);
}

static unsigned char *read_entire_file(const char *path, size_t *size_out)
{
    int             fd;
    unsigned char   *data;
    size_t          capacity;
    size_t          total;
    size_t          new_capacity;
    unsigned char   *larger;
    ssize_t         amount;

    fd = open(path, O_RDONLY);
    if (fd < 0)
    {
        fprintf(stderr, "embed_stub: cannot open %s: %s\n", path, strerror(errno));
        return (NULL);
    }
    capacity = 4096U;
    total = 0;
    data = (unsigned char *)malloc(capacity);
    if (data == NULL)
    {
        report_error("out of memory while reading object");
        close(fd);
        return (NULL);
    }
    while (1)
    {
        if (total == capacity)
        {
            if (capacity > SIZE_MAX / 2U)
            {
                report_error("object is too large to read");
                free(data);
                close(fd);
                return (NULL);
            }
            new_capacity = capacity * 2U;
            larger = (unsigned char *)malloc(new_capacity);
            if (larger == NULL)
            {
                report_error("out of memory while expanding object buffer");
                free(data);
                close(fd);
                return (NULL);
            }
            memcpy(larger, data, total);
            free(data);
            data = larger;
            capacity = new_capacity;
        }
        amount = read(fd, data + total, capacity - total);
        if (amount < 0 && errno == EINTR)
            continue ;
        if (amount < 0)
        {
            fprintf(stderr, "embed_stub: failed reading %s: %s\n", path, strerror(errno));
            free(data);
            close(fd);
            return (NULL);
        }
        if (amount == 0)
            break ;
        total += (size_t)amount;
    }
    if (close(fd) < 0)
    {
        fprintf(stderr, "embed_stub: failed closing %s: %s\n", path, strerror(errno));
        free(data);
        return (NULL);
    }
    *size_out = total;
    return (data);
}

static int write_all(int fd, const unsigned char *data, size_t size)
{
    size_t  done;
    ssize_t amount;

    done = 0;
    while (done < size)
    {
        amount = write(fd, data + done, size - done);
        if (amount < 0 && errno == EINTR)
            continue;
        if (amount <= 0)
            return (0);
        done += (size_t)amount;
    }
    return (1);
}

static int write_file(const char *path, const unsigned char *data, size_t size)
{
    int     fd;
    int     ok;

    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0)
    {
        fprintf(stderr, "embed_stub: cannot create %s: %s\n", path, strerror(errno));
        return (0);
    }
    ok = write_all(fd, data, size);
    if (!ok)
        fprintf(stderr, "embed_stub: failed writing %s: %s\n", path, strerror(errno));
    if (close(fd) < 0)
    {
        fprintf(stderr, "embed_stub: failed closing %s: %s\n", path, strerror(errno));
        ok = 0;
    }
    return (ok);
}

static int buffer_reserve(t_buffer *buffer, size_t extra)
{
    size_t  required;
    size_t  capacity;
    char    *new_data;

    if (extra > SIZE_MAX - buffer->length - 1U)
        return (0);
    required = buffer->length + extra + 1U;
    if (required <= buffer->capacity)
        return (1);
    capacity = buffer->capacity == 0 ? 1024U : buffer->capacity;
    while (capacity < required)
    {
        if (capacity > SIZE_MAX / 2U)
        {
            capacity = required;
            break ;
        }
        capacity *= 2U;
    }
    new_data = (char *)malloc(capacity);
    if (new_data == NULL)
        return (0);
    if (buffer->data != NULL)
    {
        memcpy(new_data, buffer->data, buffer->length);
        free(buffer->data);
    }
    buffer->data = new_data;
    buffer->capacity = capacity;
    return (1);
}

static int buffer_appendf(t_buffer *buffer, const char *format, ...)
{
    va_list     args;
    va_list     copy;
    int         needed;

    va_start(args, format);
    va_copy(copy, args);
    needed = vsnprintf(NULL, 0, format, copy);
    va_end(copy);
    if (needed < 0 || !buffer_reserve(buffer, (size_t)needed))
    {
        va_end(args);
        return (0);
    }
    vsnprintf(buffer->data + buffer->length,
        buffer->capacity - buffer->length, format, args);
    va_end(args);
    buffer->length += (size_t)needed;
    return (1);
}

static const char *safe_string(const unsigned char *table, size_t table_size,
    uint32_t offset)
{
    if ((size_t)offset >= table_size)
        return (NULL);
    if (memchr(table + offset, '\0', table_size - offset) == NULL)
        return (NULL);
    return ((const char *)(table + offset));
}

static int append_header(t_buffer *header, const unsigned char *blob,
    size_t blob_size, const t_stub_symbols *symbols)
{
    size_t  offset;
    size_t  count;

    if (!buffer_appendf(header,
            "/* Generated by tools/embed_stub.c; do not edit by hand. */\n"
            "#ifndef %s\n# define %s\n"
            "# include <stddef.h>\n"
            "static const unsigned char %s[] = {\n",
            symbols->guard_name, symbols->guard_name, symbols->array_name))
        return (0);
    offset = 0;
    while (offset < blob_size)
    {
        if (!buffer_appendf(header, "    "))
            return (0);
        count = 0;
        while (count < 12U && offset + count < blob_size)
        {
            if (!buffer_appendf(header, "0x%02X%s", blob[offset + count],
                    (count + 1U < 12U && offset + count + 1U < blob_size)
                        ? ", " : ","))
                return (0);
            count++;
        }
        if (!buffer_appendf(header, "\n"))
            return (0);
        offset += count;
    }
    return (buffer_appendf(header,
            "};\n"
            "# define %s ((size_t)%zuU)\n"
            "# define %s ((size_t)%" PRIu64 "U)\n"
            "# define %s ((size_t)%" PRIu64 "U)\n"
            "# define %s ((size_t)%" PRIu64 "U)\n"
            "# define %s ((size_t)%" PRIu64 "U)\n"
            "#endif\n",
            symbols->size_macro, blob_size,
            symbols->count_macro, symbols->segment_count,
            symbols->table_macro, symbols->segment_table,
            symbols->key_macro, symbols->key,
            symbols->jump_macro, symbols->jump_disp));
}

static int symbol_name_index(const char *name, const t_stub_symbols *symbols)
{
    if (symbols->elf_class == ELFCLASS64)
    {
        if (strcmp(name, "woody_stub_start") == 0) return (0);
        if (strcmp(name, "woody_stub_end") == 0) return (1);
        if (strcmp(name, "woody_segment_count") == 0) return (2);
        if (strcmp(name, "woody_segment_table") == 0) return (3);
        if (strcmp(name, "woody_key") == 0) return (4);
        if (strcmp(name, "woody_jump_disp") == 0) return (5);
    }
    else
    {
        if (strcmp(name, "woody32_stub_start") == 0) return (0);
        if (strcmp(name, "woody32_stub_end") == 0) return (1);
        if (strcmp(name, "woody32_segment_count") == 0) return (2);
        if (strcmp(name, "woody32_segment_table") == 0) return (3);
        if (strcmp(name, "woody32_key") == 0) return (4);
        if (strcmp(name, "woody32_jump_disp") == 0) return (5);
    }
    return (-1);
}

static void store_symbol(t_stub_symbols *symbols, int index, uint64_t value,
    unsigned char *found)
{
    uint64_t *slots[6];

    slots[0] = &symbols->start;
    slots[1] = &symbols->end;
    slots[2] = &symbols->segment_count;
    slots[3] = &symbols->segment_table;
    slots[4] = &symbols->key;
    slots[5] = &symbols->jump_disp;
    *slots[index] = value;
    found[index] = 1;
}

static int validate_symbol_layout(const t_stub_symbols *symbols, uint64_t text_size)
{
    if (symbols->start != 0)
    {
        report_error("stub start symbol is not at the beginning of .text");
        return (0);
    }
    if (symbols->end != text_size)
    {
        report_error("stub end symbol does not match the .text size");
        return (0);
    }
    if (symbols->segment_table != symbols->segment_count + symbols->count_width)
    {
        report_error("segment metadata layout is inconsistent");
        return (0);
    }
    if (symbols->segment_count > text_size
        || symbols->count_width > text_size - symbols->segment_count
        || symbols->key > text_size || 16U > text_size - symbols->key
        || symbols->jump_disp > text_size || 4U > text_size - symbols->jump_disp
        || symbols->segment_table > text_size)
    {
        report_error("one or more stub metadata symbols are outside .text");
        return (0);
    }
    if (symbols->segment_count % symbols->count_width != 0)
    {
        report_error("segment count field is incorrectly aligned");
        return (0);
    }
    return (1);
}

static int parse_elf64(const unsigned char *file, size_t file_size,
    unsigned char **blob_out, size_t *blob_size_out, t_stub_symbols *symbols)
{
    Elf64_Ehdr      ehdr;
    Elf64_Shdr      *sections;
    Elf64_Shdr      symtab;
    Elf64_Shdr      strtab;
    Elf64_Shdr      text;
    Elf64_Sym       sym;
    const char      *name;
    const unsigned char *shstr;
    const unsigned char *strings;
    uint64_t        table_size;
    uint32_t        text_index;
    size_t          i;
    size_t          j;
    size_t          sym_count;
    unsigned char   found[6] = {0, 0, 0, 0, 0, 0};
    int             index;

    if (file_size < sizeof(ehdr))
        return (report_error("truncated ELF64 header"), 0);
    memcpy(&ehdr, file, sizeof(ehdr));
    if (ehdr.e_type != ET_REL || ehdr.e_machine != EM_X86_64
        || ehdr.e_version != EV_CURRENT || ehdr.e_ehsize != sizeof(ehdr))
        return (report_error("expected an x86-64 relocatable ELF object"), 0);
    if (ehdr.e_shentsize != sizeof(Elf64_Shdr) || ehdr.e_shnum == 0
        || ehdr.e_shstrndx == SHN_XINDEX || ehdr.e_shstrndx >= ehdr.e_shnum)
        return (report_error("unsupported or invalid ELF64 section table"), 0);
    table_size = (uint64_t)ehdr.e_shnum * sizeof(Elf64_Shdr);
    if (!range_is_valid(file_size, ehdr.e_shoff, table_size))
        return (report_error("ELF64 section table is outside the object"), 0);
    sections = (Elf64_Shdr *)malloc((size_t)ehdr.e_shnum * sizeof(*sections));
    if (sections == NULL)
        return (report_error("out of memory reading ELF64 sections"), 0);
    memset(sections, 0, (size_t)ehdr.e_shnum * sizeof(*sections));
    for (i = 0; i < ehdr.e_shnum; i++)
    {
        memcpy(&sections[i], file + (size_t)ehdr.e_shoff + i * sizeof(Elf64_Shdr),
            sizeof(Elf64_Shdr));
        if (sections[i].sh_type != SHT_NOBITS
            && !range_is_valid(file_size, sections[i].sh_offset, sections[i].sh_size))
        {
            free(sections);
            return (report_error("ELF64 section extends beyond the object"), 0);
        }
        if ((sections[i].sh_type == SHT_REL || sections[i].sh_type == SHT_RELA)
            && sections[i].sh_size != 0)
        {
            free(sections);
            return (report_error("stub object contains relocations; raw embedded code must be position-independent"), 0);
        }
    }
    if (sections[ehdr.e_shstrndx].sh_type != SHT_STRTAB)
    {
        free(sections);
        return (report_error("invalid ELF64 section-name string table"), 0);
    }
    shstr = file + sections[ehdr.e_shstrndx].sh_offset;
    text_index = UINT32_MAX;
    memset(&text, 0, sizeof(text));
    for (i = 0; i < ehdr.e_shnum; i++)
    {
        name = safe_string(shstr, (size_t)sections[ehdr.e_shstrndx].sh_size,
                sections[i].sh_name);
        if (name == NULL)
        {
            free(sections);
            return (report_error("invalid section name in ELF64 object"), 0);
        }
        if (strcmp(name, ".text") == 0)
        {
            text_index = (uint32_t)i;
            text = sections[i];
        }
    }
    if (text_index == UINT32_MAX || text.sh_type != SHT_PROGBITS
        || (text.sh_flags & SHF_EXECINSTR) == 0 || text.sh_size == 0)
    {
        free(sections);
        return (report_error("ELF64 object has no executable .text section"), 0);
    }
    memset(&symtab, 0, sizeof(symtab));
    memset(&strtab, 0, sizeof(strtab));
    for (i = 0; i < ehdr.e_shnum; i++)
    {
        if (sections[i].sh_type == SHT_SYMTAB)
        {
            if (sections[i].sh_entsize != sizeof(Elf64_Sym)
                || sections[i].sh_size % sizeof(Elf64_Sym) != 0
                || sections[i].sh_link >= ehdr.e_shnum
                || sections[sections[i].sh_link].sh_type != SHT_STRTAB)
            {
                free(sections);
                return (report_error("invalid ELF64 symbol table"), 0);
            }
            symtab = sections[i];
            strtab = sections[sections[i].sh_link];
            break ;
        }
    }
    if (symtab.sh_type != SHT_SYMTAB)
    {
        free(sections);
        return (report_error("ELF64 object has no symbol table"), 0);
    }
    strings = file + strtab.sh_offset;
    sym_count = (size_t)(symtab.sh_size / sizeof(Elf64_Sym));
    for (j = 0; j < sym_count; j++)
    {
        memcpy(&sym, file + symtab.sh_offset + j * sizeof(sym), sizeof(sym));
        name = safe_string(strings, (size_t)strtab.sh_size, sym.st_name);
        if (name == NULL)
        {
            free(sections);
            return (report_error("invalid ELF64 symbol name"), 0);
        }
        index = symbol_name_index(name, symbols);
        if (index >= 0)
        {
            if (found[index] || sym.st_shndx != text_index || sym.st_value > text.sh_size)
            {
                free(sections);
                return (report_error("stub symbol is duplicated or outside .text"), 0);
            }
            store_symbol(symbols, index, sym.st_value, found);
        }
    }
    free(sections);
    for (i = 0; i < 6; i++)
    {
        if (!found[i])
            return (report_error("ELF64 stub is missing a required metadata symbol"), 0);
    }
    if (!validate_symbol_layout(symbols, text.sh_size))
        return (0);
    *blob_size_out = (size_t)text.sh_size;
    *blob_out = (unsigned char *)malloc(*blob_size_out);
    if (*blob_out == NULL)
        return (report_error("out of memory copying ELF64 .text"), 0);
    memcpy(*blob_out, file + text.sh_offset, *blob_size_out);
    return (1);
}

static int parse_elf32(const unsigned char *file, size_t file_size,
    unsigned char **blob_out, size_t *blob_size_out, t_stub_symbols *symbols)
{
    Elf32_Ehdr      ehdr;
    Elf32_Shdr      *sections;
    Elf32_Shdr      symtab;
    Elf32_Shdr      strtab;
    Elf32_Shdr      text;
    Elf32_Sym       sym;
    const char      *name;
    const unsigned char *shstr;
    const unsigned char *strings;
    uint64_t        table_size;
    uint32_t        text_index;
    size_t          i;
    size_t          j;
    size_t          sym_count;
    unsigned char   found[6] = {0, 0, 0, 0, 0, 0};
    int             index;

    if (file_size < sizeof(ehdr))
        return (report_error("truncated ELF32 header"), 0);
    memcpy(&ehdr, file, sizeof(ehdr));
    if (ehdr.e_type != ET_REL || ehdr.e_machine != EM_386
        || ehdr.e_version != EV_CURRENT || ehdr.e_ehsize != sizeof(ehdr))
        return (report_error("expected an i386 relocatable ELF object"), 0);
    if (ehdr.e_shentsize != sizeof(Elf32_Shdr) || ehdr.e_shnum == 0
        || ehdr.e_shstrndx == SHN_XINDEX || ehdr.e_shstrndx >= ehdr.e_shnum)
        return (report_error("unsupported or invalid ELF32 section table"), 0);
    table_size = (uint64_t)ehdr.e_shnum * sizeof(Elf32_Shdr);
    if (!range_is_valid(file_size, ehdr.e_shoff, table_size))
        return (report_error("ELF32 section table is outside the object"), 0);
    sections = (Elf32_Shdr *)malloc((size_t)ehdr.e_shnum * sizeof(*sections));
    if (sections == NULL)
        return (report_error("out of memory reading ELF32 sections"), 0);
    memset(sections, 0, (size_t)ehdr.e_shnum * sizeof(*sections));
    for (i = 0; i < ehdr.e_shnum; i++)
    {
        memcpy(&sections[i], file + (size_t)ehdr.e_shoff + i * sizeof(Elf32_Shdr),
            sizeof(Elf32_Shdr));
        if (sections[i].sh_type != SHT_NOBITS
            && !range_is_valid(file_size, sections[i].sh_offset, sections[i].sh_size))
        {
            free(sections);
            return (report_error("ELF32 section extends beyond the object"), 0);
        }
        if ((sections[i].sh_type == SHT_REL || sections[i].sh_type == SHT_RELA)
            && sections[i].sh_size != 0)
        {
            free(sections);
            return (report_error("i386 stub object contains relocations; raw embedded code must be position-independent"), 0);
        }
    }
    if (sections[ehdr.e_shstrndx].sh_type != SHT_STRTAB)
    {
        free(sections);
        return (report_error("invalid ELF32 section-name string table"), 0);
    }
    shstr = file + sections[ehdr.e_shstrndx].sh_offset;
    text_index = UINT32_MAX;
    memset(&text, 0, sizeof(text));
    for (i = 0; i < ehdr.e_shnum; i++)
    {
        name = safe_string(shstr, (size_t)sections[ehdr.e_shstrndx].sh_size,
                sections[i].sh_name);
        if (name == NULL)
        {
            free(sections);
            return (report_error("invalid section name in ELF32 object"), 0);
        }
        if (strcmp(name, ".text") == 0)
        {
            text_index = (uint32_t)i;
            text = sections[i];
        }
    }
    if (text_index == UINT32_MAX || text.sh_type != SHT_PROGBITS
        || (text.sh_flags & SHF_EXECINSTR) == 0 || text.sh_size == 0)
    {
        free(sections);
        return (report_error("ELF32 object has no executable .text section"), 0);
    }
    memset(&symtab, 0, sizeof(symtab));
    memset(&strtab, 0, sizeof(strtab));
    for (i = 0; i < ehdr.e_shnum; i++)
    {
        if (sections[i].sh_type == SHT_SYMTAB)
        {
            if (sections[i].sh_entsize != sizeof(Elf32_Sym)
                || sections[i].sh_size % sizeof(Elf32_Sym) != 0
                || sections[i].sh_link >= ehdr.e_shnum
                || sections[sections[i].sh_link].sh_type != SHT_STRTAB)
            {
                free(sections);
                return (report_error("invalid ELF32 symbol table"), 0);
            }
            symtab = sections[i];
            strtab = sections[sections[i].sh_link];
            break ;
        }
    }
    if (symtab.sh_type != SHT_SYMTAB)
    {
        free(sections);
        return (report_error("ELF32 object has no symbol table"), 0);
    }
    strings = file + strtab.sh_offset;
    sym_count = (size_t)(symtab.sh_size / sizeof(Elf32_Sym));
    for (j = 0; j < sym_count; j++)
    {
        memcpy(&sym, file + symtab.sh_offset + j * sizeof(sym), sizeof(sym));
        name = safe_string(strings, (size_t)strtab.sh_size, sym.st_name);
        if (name == NULL)
        {
            free(sections);
            return (report_error("invalid ELF32 symbol name"), 0);
        }
        index = symbol_name_index(name, symbols);
        if (index >= 0)
        {
            if (found[index] || sym.st_shndx != text_index || sym.st_value > text.sh_size)
            {
                free(sections);
                return (report_error("i386 stub symbol is duplicated or outside .text"), 0);
            }
            store_symbol(symbols, index, sym.st_value, found);
        }
    }
    free(sections);
    for (i = 0; i < 6; i++)
    {
        if (!found[i])
            return (report_error("ELF32 stub is missing a required metadata symbol"), 0);
    }
    if (!validate_symbol_layout(symbols, text.sh_size))
        return (0);
    *blob_size_out = (size_t)text.sh_size;
    *blob_out = (unsigned char *)malloc(*blob_size_out);
    if (*blob_out == NULL)
        return (report_error("out of memory copying ELF32 .text"), 0);
    memcpy(*blob_out, file + text.sh_offset, *blob_size_out);
    return (1);
}

static void configure_symbols(t_stub_symbols *symbols, unsigned elf_class)
{
    memset(symbols, 0, sizeof(*symbols));
    symbols->elf_class = elf_class;
    if (elf_class == ELFCLASS64)
    {
        symbols->array_name = "g_woody_stub";
        symbols->guard_name = "WOODY_STUB_BLOB_H";
        symbols->size_macro = "WOODY_STUB_SIZE";
        symbols->count_macro = "STUB_SEGMENT_COUNT_OFFSET";
        symbols->table_macro = "STUB_SEGMENT_TABLE_OFFSET";
        symbols->key_macro = "STUB_KEY_OFFSET";
        symbols->jump_macro = "STUB_JUMP_DISP_OFFSET";
        symbols->count_width = 8U;
    }
    else
    {
        symbols->array_name = "g_woody_stub32";
        symbols->guard_name = "WOODY_STUB32_BLOB_H";
        symbols->size_macro = "WOODY32_STUB_SIZE";
        symbols->count_macro = "STUB32_SEGMENT_COUNT_OFFSET";
        symbols->table_macro = "STUB32_SEGMENT_TABLE_OFFSET";
        symbols->key_macro = "STUB32_KEY_OFFSET";
        symbols->jump_macro = "STUB32_JUMP_DISP_OFFSET";
        symbols->count_width = 4U;
    }
}

int main(int argc, char **argv)
{
    unsigned char       *file;
    unsigned char       *blob;
    size_t              file_size;
    size_t              blob_size;
    t_stub_symbols      symbols;
    t_buffer            header;
    unsigned            elf_class;
    int                 ok;

    if (argc != 4)
    {
        fprintf(stderr, "usage: %s stub.o stub.bin output.h\n", argv[0]);
        return (2);
    }
    file = read_entire_file(argv[1], &file_size);
    if (file == NULL)
        return (1);
    if (file_size < EI_NIDENT || memcmp(file, ELFMAG, SELFMAG) != 0
        || file[EI_DATA] != ELFDATA2LSB || file[EI_VERSION] != EV_CURRENT)
    {
        free(file);
        report_error("input is not a little-endian ELF object");
        return (1);
    }
    elf_class = file[EI_CLASS];
    if (elf_class != ELFCLASS32 && elf_class != ELFCLASS64)
    {
        free(file);
        report_error("unsupported ELF class");
        return (1);
    }
    configure_symbols(&symbols, elf_class);
    if ((elf_class == ELFCLASS64 && file[EI_OSABI] != ELFOSABI_NONE
            && file[EI_OSABI] != ELFOSABI_LINUX)
        || (elf_class == ELFCLASS32 && file[EI_OSABI] != ELFOSABI_NONE
            && file[EI_OSABI] != ELFOSABI_LINUX))
    {
        free(file);
        report_error("unsupported ELF ABI for embedded stub object");
        return (1);
    }
    blob = NULL;
    blob_size = 0;
    if (elf_class == ELFCLASS64)
        ok = parse_elf64(file, file_size, &blob, &blob_size, &symbols);
    else
        ok = parse_elf32(file, file_size, &blob, &blob_size, &symbols);
    free(file);
    if (!ok)
        return (1);
    memset(&header, 0, sizeof(header));
    if (!append_header(&header, blob, blob_size, &symbols))
    {
        free(blob);
        free(header.data);
        report_error("out of memory generating C header");
        return (1);
    }
    if (!write_file(argv[2], blob, blob_size)
        || !write_file(argv[3], (const unsigned char *)header.data,
            header.length))
    {
        free(blob);
        free(header.data);
        return (1);
    }
    free(blob);
    free(header.data);
    return (0);
}