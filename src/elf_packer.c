#include "woody.h"
#include "woody_stub_blob.h"

static void copy_bytes(unsigned char *dst, const unsigned char *src, size_t size)
{
    size_t i;

    i = 0;
    while (i < size)
    {
        dst[i] = src[i];
        i++;
    }
}

static void zero_bytes(unsigned char *dst, size_t size)
{
    size_t i;

    i = 0;
    while (i < size)
    {
        dst[i] = 0;
        i++;
    }
}

static int is_power_of_two(uint64_t value)
{
    return (value != 0 && (value & (value - 1U)) == 0);
}

static int align_up_u64(uint64_t value, uint64_t alignment, uint64_t *result)
{
    uint64_t remainder;
    uint64_t add;

    if (!is_power_of_two(alignment))
        return (-1);
    remainder = value & (alignment - 1U);
    add = remainder == 0 ? 0 : alignment - remainder;
    if (value > UINT64_MAX - add)
        return (-1);
    *result = value + add;
    return (0);
}

static uint64_t align_down_u64(uint64_t value, uint64_t alignment)
{
    return (value & ~(alignment - 1U));
}

static int range_is_inside(uint64_t offset, uint64_t length, size_t total)
{
    if (offset > (uint64_t)total)
        return (0);
    if (length > (uint64_t)total - offset)
        return (0);
    return (1);
}

static void write_u32_le(unsigned char *dst, uint32_t value)
{
    dst[0] = (unsigned char)value;
    dst[1] = (unsigned char)(value >> 8);
    dst[2] = (unsigned char)(value >> 16);
    dst[3] = (unsigned char)(value >> 24);
}

static void write_u64_le(unsigned char *dst, uint64_t value)
{
    write_u32_le(dst, (uint32_t)value);
    write_u32_le(dst + 4, (uint32_t)(value >> 32));
}

static uint32_t read_u32_le(const unsigned char *src)
{
    return ((uint32_t)src[0]
        | ((uint32_t)src[1] << 8)
        | ((uint32_t)src[2] << 16)
        | ((uint32_t)src[3] << 24));
}

static uint32_t elf_flags_to_prot(uint32_t flags)
{
    uint32_t prot;

    prot = 0;
    if (flags & PF_R)
        prot |= PROT_READ;
    if (flags & PF_W)
        prot |= PROT_WRITE;
    if (flags & PF_X)
        prot |= PROT_EXEC;
    return (prot);
}

static int validate_elf(const unsigned char *input, size_t input_size,
        const Elf64_Ehdr **ehdr_out, const Elf64_Phdr **phdr_out,
        size_t **exec_indices_out, size_t *exec_count_out,
        uint64_t *max_vaddr_end_out, size_t *pt_phdr_count_out)
{
    const Elf64_Ehdr *ehdr;
    const Elf64_Phdr *phdr;
    size_t *exec_indices;
    size_t i;
    size_t exec_count;
    size_t pt_phdr_count;
    size_t interp_count;
    size_t dynamic_count;
    size_t phdr_index;
    size_t interp_index;
    size_t first_load_index;
    uint64_t max_vaddr_end;
    uint64_t segment_end;
    int found_entry;

    *exec_indices_out = NULL;
    *exec_count_out = 0;
    if (input_size < sizeof(Elf64_Ehdr))
        return (fprintf(stderr, "woody: file is smaller than an ELF64 header\n"), -1);
    ehdr = (const Elf64_Ehdr *)input;
    if (ehdr->e_ident[EI_MAG0] != ELFMAG0
        || ehdr->e_ident[EI_MAG1] != ELFMAG1
        || ehdr->e_ident[EI_MAG2] != ELFMAG2
        || ehdr->e_ident[EI_MAG3] != ELFMAG3)
        return (fprintf(stderr, "woody: input is not an ELF file\n"), -1);
    if (ehdr->e_ident[EI_CLASS] != ELFCLASS64
        || ehdr->e_ident[EI_DATA] != ELFDATA2LSB
        || ehdr->e_machine != EM_X86_64)
        return (fprintf(stderr, "woody: unsupported architecture; x86_64 ELF64 only\n"), -1);
    if (ehdr->e_ident[EI_VERSION] != EV_CURRENT
        || ehdr->e_version != EV_CURRENT
        || ehdr->e_ehsize != sizeof(Elf64_Ehdr)
        || ehdr->e_phentsize != sizeof(Elf64_Phdr))
        return (fprintf(stderr, "woody: malformed or unsupported ELF header\n"), -1);
    if (ehdr->e_type != ET_EXEC && ehdr->e_type != ET_DYN)
        return (fprintf(stderr, "woody: only ET_EXEC and ET_DYN executables are supported\n"), -1);
    if (ehdr->e_phnum == 0 || ehdr->e_phnum == PN_XNUM)
        return (fprintf(stderr, "woody: missing or extended program-header table is unsupported\n"), -1);
    if ((ehdr->e_phoff % 8U) != 0
        || !range_is_inside(ehdr->e_phoff,
            (uint64_t)ehdr->e_phnum * sizeof(Elf64_Phdr), input_size))
        return (fprintf(stderr, "woody: program-header table is outside the file\n"), -1);

    phdr = (const Elf64_Phdr *)(input + ehdr->e_phoff);
    exec_indices = (size_t *)malloc((size_t)ehdr->e_phnum * sizeof(size_t));
    if (exec_indices == NULL)
        return (perror("malloc"), -1);
    exec_count = 0;
    pt_phdr_count = 0;
    interp_count = 0;
    dynamic_count = 0;
    phdr_index = SIZE_MAX;
    interp_index = SIZE_MAX;
    first_load_index = SIZE_MAX;
    max_vaddr_end = 0;
    found_entry = 0;
    i = 0;
    while (i < ehdr->e_phnum)
    {
        if (phdr[i].p_type == PT_PHDR)
        {
            pt_phdr_count++;
            phdr_index = i;
        }
        else if (phdr[i].p_type == PT_INTERP)
        {
            interp_count++;
            interp_index = i;
            if (phdr[i].p_filesz < 2
                || !range_is_inside(phdr[i].p_offset, phdr[i].p_filesz, input_size)
                || input[phdr[i].p_offset + phdr[i].p_filesz - 1U] != '\0')
            {
                free(exec_indices);
                return (fprintf(stderr, "woody: malformed PT_INTERP segment\n"), -1);
            }
        }
        else if (phdr[i].p_type == PT_DYNAMIC)
        {
            dynamic_count++;
            if (phdr[i].p_filesz > phdr[i].p_memsz
                || phdr[i].p_filesz % sizeof(Elf64_Dyn) != 0
                || !range_is_inside(phdr[i].p_offset, phdr[i].p_filesz, input_size))
            {
                free(exec_indices);
                return (fprintf(stderr, "woody: malformed PT_DYNAMIC segment\n"), -1);
            }
        }
        if (phdr[i].p_type == PT_LOAD)
        {
            if (first_load_index == SIZE_MAX)
                first_load_index = i;
            if (phdr[i].p_filesz > phdr[i].p_memsz
                || !range_is_inside(phdr[i].p_offset, phdr[i].p_filesz, input_size))
            {
                free(exec_indices);
                return (fprintf(stderr, "woody: invalid PT_LOAD file range\n"), -1);
            }
            if (phdr[i].p_vaddr > UINT64_MAX - phdr[i].p_memsz)
            {
                free(exec_indices);
                return (fprintf(stderr, "woody: PT_LOAD virtual-address overflow\n"), -1);
            }
            if (phdr[i].p_align > 1
                && (!is_power_of_two(phdr[i].p_align)
                    || (phdr[i].p_vaddr % phdr[i].p_align)
                        != (phdr[i].p_offset % phdr[i].p_align)))
            {
                free(exec_indices);
                return (fprintf(stderr, "woody: invalid PT_LOAD alignment\n"), -1);
            }
            if ((phdr[i].p_vaddr & (WOODY_PAGE_SIZE - 1U))
                != (phdr[i].p_offset & (WOODY_PAGE_SIZE - 1U)))
            {
                free(exec_indices);
                return (fprintf(stderr, "woody: PT_LOAD violates system-page offset congruence\n"), -1);
            }
            segment_end = phdr[i].p_vaddr + phdr[i].p_memsz;
            if (segment_end > max_vaddr_end)
                max_vaddr_end = segment_end;
            if ((phdr[i].p_flags & PF_X) && phdr[i].p_filesz > 0)
            {
                exec_indices[exec_count++] = i;
                if (ehdr->e_entry >= phdr[i].p_vaddr
                    && ehdr->e_entry - phdr[i].p_vaddr < phdr[i].p_filesz)
                    found_entry++;
            }
        }
        i++;
    }
    if (pt_phdr_count > 1 || interp_count > 1 || dynamic_count > 1)
    {
        free(exec_indices);
        return (fprintf(stderr, "woody: duplicate PT_PHDR, PT_INTERP or PT_DYNAMIC entries\n"), -1);
    }
    if ((pt_phdr_count == 1 && phdr_index > first_load_index)
        || (interp_count == 1 && interp_index > first_load_index))
    {
        free(exec_indices);
        return (fprintf(stderr, "woody: PT_PHDR and PT_INTERP must precede PT_LOAD entries\n"), -1);
    }
    if (exec_count == 0 || found_entry != 1)
    {
        free(exec_indices);
        return (fprintf(stderr, "woody: entry point must belong to exactly one file-backed executable PT_LOAD\n"), -1);
    }
    *ehdr_out = ehdr;
    *phdr_out = phdr;
    *exec_indices_out = exec_indices;
    *exec_count_out = exec_count;
    *max_vaddr_end_out = max_vaddr_end;
    *pt_phdr_count_out = pt_phdr_count;
    return (0);
}

static int check_executable_pages_isolated(const Elf64_Phdr *phdr,
        size_t phnum, size_t input_size,
        const size_t *exec_indices, size_t exec_count)
{
    uint64_t target_begin;
    uint64_t target_end;
    uint64_t other_begin;
    uint64_t other_end;
    uint64_t target_file_end;
    uint64_t other_file_end;
    size_t target_index;
    size_t i;
    size_t j;

    i = 0;
    while (i < exec_count)
    {
        target_index = exec_indices[i];
        target_begin = align_down_u64(phdr[target_index].p_vaddr, WOODY_PAGE_SIZE);
        if (align_up_u64(phdr[target_index].p_vaddr + phdr[target_index].p_memsz,
                WOODY_PAGE_SIZE, &target_end) < 0)
            return (fprintf(stderr, "woody: executable segment page range overflows\n"), -1);
        target_file_end = phdr[target_index].p_offset + phdr[target_index].p_filesz;
        j = 0;
        while (j < phnum)
        {
            if (j != target_index && phdr[j].p_type != PT_NULL
                && phdr[j].p_filesz > 0)
            {
                if (!range_is_inside(phdr[j].p_offset, phdr[j].p_filesz, input_size))
                    return (fprintf(stderr, "woody: program segment file range is outside the input\n"), -1);
                other_file_end = phdr[j].p_offset + phdr[j].p_filesz;
                if (phdr[target_index].p_offset < other_file_end
                    && phdr[j].p_offset < target_file_end)
                    return (fprintf(stderr,
                        "woody: executable file range overlaps another program segment\n"), -1);
            }
            if (j != target_index && phdr[j].p_type == PT_LOAD
                && phdr[j].p_memsz > 0)
            {
                other_begin = align_down_u64(phdr[j].p_vaddr, WOODY_PAGE_SIZE);
                if (align_up_u64(phdr[j].p_vaddr + phdr[j].p_memsz,
                        WOODY_PAGE_SIZE, &other_end) < 0)
                    return (fprintf(stderr, "woody: PT_LOAD page range overflows\n"), -1);
                if (target_begin < other_end && other_begin < target_end)
                    return (fprintf(stderr,
                        "woody: executable PT_LOAD shares a memory page with another PT_LOAD\n"), -1);
            }
#ifdef PT_GNU_RELRO
            if (phdr[j].p_type == PT_GNU_RELRO && phdr[j].p_memsz > 0)
            {
                if (phdr[j].p_vaddr > UINT64_MAX - phdr[j].p_memsz)
                    return (fprintf(stderr, "woody: PT_GNU_RELRO virtual range overflows\n"), -1);
                other_begin = align_down_u64(phdr[j].p_vaddr, WOODY_PAGE_SIZE);
                if (align_up_u64(phdr[j].p_vaddr + phdr[j].p_memsz,
                        WOODY_PAGE_SIZE, &other_end) < 0)
                    return (fprintf(stderr, "woody: PT_GNU_RELRO page range overflows\n"), -1);
                if (target_begin < other_end && other_begin < target_end)
                    return (fprintf(stderr,
                        "woody: executable PT_LOAD overlaps PT_GNU_RELRO pages\n"), -1);
            }
#endif
            j++;
        }
        i++;
    }
    return (0);
}

static int patch_stub(unsigned char *stub, uint64_t stub_vaddr,
        const Elf64_Ehdr *ehdr, const Elf64_Phdr *phdr,
        const size_t *exec_indices, size_t exec_count,
        const unsigned char key[WOODY_KEY_SIZE], uint64_t nonce)
{
    int64_t jump_delta;
    uint64_t jump_next;
    uint64_t counter_offset;
    uint64_t blocks;
    uint64_t total_blocks;
    uint64_t segment_nonce;
    size_t i;
    size_t index;
    unsigned char *record;

    if (stub_vaddr > UINT64_MAX - STUB_JUMP_DISP_OFFSET - 4U)
        return (fprintf(stderr, "woody: stub jump address overflows\n"), -1);
    jump_next = stub_vaddr + STUB_JUMP_DISP_OFFSET + 4U;
    if (ehdr->e_entry >= jump_next)
    {
        if (ehdr->e_entry - jump_next > INT32_MAX)
            return (fprintf(stderr, "woody: original entry point is outside rel32 jump range\n"), -1);
        jump_delta = (int64_t)(ehdr->e_entry - jump_next);
    }
    else
    {
        if (jump_next - ehdr->e_entry > (uint64_t)INT32_MAX + 1U)
            return (fprintf(stderr, "woody: original entry point is outside rel32 jump range\n"), -1);
        jump_delta = -(int64_t)(jump_next - ehdr->e_entry);
    }
    write_u32_le(stub + STUB_JUMP_DISP_OFFSET, (uint32_t)(int32_t)jump_delta);
    write_u64_le(stub + STUB_SEGMENT_COUNT_OFFSET, (uint64_t)exec_count);
    i = 0;
    while (i < WOODY_KEY_SIZE)
    {
        stub[STUB_KEY_OFFSET + i] = key[i];
        i++;
    }
    counter_offset = 0;
    total_blocks = 0;
    i = 0;
    while (i < exec_count)
    {
        index = exec_indices[i];
        blocks = phdr[index].p_filesz / 8U
            + (phdr[index].p_filesz % 8U != 0 ? 1U : 0U);
        if (total_blocks > UINT64_MAX - blocks)
            return (fprintf(stderr, "woody: total encrypted size overflows CTR counter space\n"), -1);
        total_blocks += blocks;
        i++;
    }
    if (total_blocks == 0 || nonce > UINT64_MAX - (total_blocks - 1U))
        return (fprintf(stderr, "woody: nonce range would overflow XTEA-CTR counter space\n"), -1);

    i = 0;
    while (i < exec_count)
    {
        index = exec_indices[i];
        blocks = phdr[index].p_filesz / 8U
            + (phdr[index].p_filesz % 8U != 0 ? 1U : 0U);
        segment_nonce = nonce + counter_offset;
        record = stub + STUB_SEGMENT_TABLE_OFFSET
            + i * WOODY_SEGMENT_DESC_SIZE;
        write_u64_le(record, phdr[index].p_vaddr - stub_vaddr);
        write_u64_le(record + 8U, phdr[index].p_vaddr - stub_vaddr);
        write_u64_le(record + 16U, phdr[index].p_filesz);
        write_u64_le(record + 24U, phdr[index].p_filesz);
        write_u64_le(record + 32U, segment_nonce);
        write_u32_le(record + 40U, elf_flags_to_prot(phdr[index].p_flags));
        write_u32_le(record + 44U, 0);
        write_u32_le(record + 48U, 0);
        write_u32_le(record + 52U, 0);
        counter_offset += blocks;
        i++;
    }
    return (0);
}

typedef struct s_compressed_segment
{
    size_t index;
    uint64_t remove_length;
    uint64_t payload_offset;
    size_t payload_length;
    unsigned char *payload;
    uint32_t flags;
    uint64_t nonce;
} t_compressed_segment;

static void free_compressed_segments(t_compressed_segment *items, size_t count)
{
    size_t i;

    if (items == NULL)
        return;
    i = 0;
    while (i < count)
    {
        free(items[i].payload);
        i++;
    }
    free(items);
}

static int pack_elf_compressed(const unsigned char *input, size_t input_size,
        unsigned char **output, size_t *output_size,
        const unsigned char key_bytes[WOODY_KEY_SIZE], uint64_t nonce,
        const Elf64_Ehdr *ehdr, const Elf64_Phdr *phdr,
        const size_t *exec_indices, size_t exec_count,
        uint64_t max_vaddr_end, size_t pt_phdr_count)
{
    t_compressed_segment *items;
    uint64_t *remove_starts;
    uint64_t *remove_lengths;
    Elf64_Ehdr *out_ehdr;
    Elf64_Phdr *out_phdr;
    Elf64_Phdr new_code_load;
    Elf64_Phdr new_data_load;
    Elf64_Phdr new_phdr;
    unsigned char *result;
    unsigned char *stub;
    unsigned char *record;
    uint32_t key_words[4];
    uint64_t removed_total;
    uint64_t original_payload_total;
    uint64_t compact_size;
    uint64_t phdr_bytes;
    uint64_t new_phnum;
    uint64_t new_offset;
    uint64_t new_vaddr;
    uint64_t stub_offset;
    uint64_t stub_total_size;
    uint64_t code_segment_size;
    uint64_t data_offset;
    uint64_t data_vaddr;
    uint64_t payload_cursor;
    uint64_t data_size;
    uint64_t total_size;
    uint64_t stub_vaddr;
    uint64_t total_blocks;
    uint64_t counter_offset;
    uint64_t blocks;
    uint64_t jump_next;
    int64_t jump_delta;
    uint64_t shift;
    uint64_t old_offset;
    uint64_t rebased_offset;
    uint64_t copy_src;
    uint64_t copy_dst;
    uint64_t range_end;
    uint64_t prior_end;
    size_t i;
    size_t j;
    size_t old_phnum;
    size_t code_index;
    size_t data_index;
    int is_exec;

    items = NULL;
    remove_starts = NULL;
    remove_lengths = NULL;
    result = NULL;
    *output = NULL;
    *output_size = 0;
    old_phnum = ehdr->e_phnum;
    items = (t_compressed_segment *)calloc(exec_count, sizeof(*items));
    remove_starts = (uint64_t *)malloc(exec_count * sizeof(*remove_starts));
    remove_lengths = (uint64_t *)malloc(exec_count * sizeof(*remove_lengths));
    if (items == NULL || remove_starts == NULL || remove_lengths == NULL)
    {
        perror("malloc compression metadata");
        goto fail;
    }
    for (i = 0; i < exec_count; i++)
    {
        items[i].index = exec_indices[i];
        items[i].payload = NULL;
        items[i].payload_length = 0;
        items[i].flags = 0;
        items[i].nonce = 0;
        items[i].payload_offset = 0;
        items[i].remove_length = 0;
    }
    for (i = 1; i < exec_count; i++)
    {
        t_compressed_segment current = items[i];
        j = i;
        while (j > 0 && phdr[items[j - 1U].index].p_offset
                > phdr[current.index].p_offset)
        {
            items[j] = items[j - 1U];
            j--;
        }
        items[j] = current;
    }
    removed_total = 0;
    original_payload_total = 0;
    prior_end = 0;
    for (i = 0; i < exec_count; i++)
    {
        const Elf64_Phdr *p = &phdr[items[i].index];
        uint64_t rounded;

        if ((p->p_offset & (WOODY_PAGE_SIZE - 1U)) != 0
            || p->p_offset < sizeof(Elf64_Ehdr)
            || align_up_u64(p->p_filesz, WOODY_PAGE_SIZE, &rounded) < 0
            || p->p_offset > input_size
            || (i > 0 && p->p_offset < prior_end))
        {
            fprintf(stderr, "woody: --compress requires page-aligned, non-overlapping executable file ranges\n");
            goto fail;
        }
        if (rounded > input_size - p->p_offset)
            rounded = input_size - p->p_offset;
        if (rounded == 0 || p->p_offset > UINT64_MAX - rounded)
        {
            fprintf(stderr, "woody: invalid executable removal range\n");
            goto fail;
        }
        range_end = p->p_offset + rounded;
        for (j = 0; j < old_phnum; j++)
        {
            uint64_t other_end;
            if (j == items[i].index || phdr[j].p_type == PT_NULL
                || phdr[j].p_filesz == 0)
                continue;
            other_end = phdr[j].p_offset + phdr[j].p_filesz;
            if (p->p_offset < other_end && phdr[j].p_offset < range_end)
            {
                fprintf(stderr, "woody: --compress cannot remove executable padding referenced by another program header\n");
                goto fail;
            }
        }
        items[i].remove_length = rounded;
        remove_starts[i] = p->p_offset;
        remove_lengths[i] = rounded;
        if (original_payload_total > UINT64_MAX - p->p_filesz)
        {
            fprintf(stderr, "woody: original executable payload size overflow\n");
            goto fail;
        }
        original_payload_total += p->p_filesz;
        if (removed_total > UINT64_MAX - rounded)
        {
            fprintf(stderr, "woody: compressed input size overflow\n");
            goto fail;
        }
        removed_total += rounded;
        prior_end = range_end;
    }
    if (removed_total >= input_size || removed_total > input_size - sizeof(Elf64_Ehdr))
    {
        fprintf(stderr, "woody: executable ranges leave no valid ELF header after compaction\n");
        goto fail;
    }
    compact_size = input_size - removed_total;
    payload_cursor = 0;
    total_blocks = 0;
    for (i = 0; i < exec_count; i++)
    {
        const Elf64_Phdr *p = &phdr[items[i].index];
        unsigned char *compressed;
        size_t compressed_size;

        compressed = NULL;
        compressed_size = 0;
        if (woody_lzss_compress(input + p->p_offset, (size_t)p->p_filesz,
                &compressed, &compressed_size) < 0)
            goto fail;
        if (compressed_size < p->p_filesz)
        {
            items[i].payload = compressed;
            items[i].payload_length = compressed_size;
            items[i].flags = 1U;
        }
        else
        {
            free(compressed);
            items[i].payload = (unsigned char *)malloc((size_t)p->p_filesz);
            if (items[i].payload == NULL)
            {
                perror("malloc raw payload");
                goto fail;
            }
            copy_bytes(items[i].payload, input + p->p_offset, (size_t)p->p_filesz);
            items[i].payload_length = (size_t)p->p_filesz;
            items[i].flags = 0U;
        }
        if (align_up_u64(payload_cursor, 16U, &payload_cursor) < 0)
        {
            fprintf(stderr, "woody: compressed payload layout overflow\n");
            goto fail;
        }
        items[i].payload_offset = payload_cursor;
        if (payload_cursor > UINT64_MAX - items[i].payload_length)
        {
            fprintf(stderr, "woody: compressed payload size overflow\n");
            goto fail;
        }
        payload_cursor += items[i].payload_length;
        blocks = items[i].payload_length / 8U
            + (items[i].payload_length % 8U != 0 ? 1U : 0U);
        if (total_blocks > UINT64_MAX - blocks)
        {
            fprintf(stderr, "woody: compressed CTR counter range overflow\n");
            goto fail;
        }
        total_blocks += blocks;
    }
    if (total_blocks == 0 || nonce > UINT64_MAX - (total_blocks - 1U))
    {
        fprintf(stderr, "woody: compressed nonce range would overflow XTEA-CTR counter space\n");
        goto fail;
    }
    if (align_up_u64(payload_cursor, WOODY_PAGE_SIZE, &data_size) < 0)
    {
        fprintf(stderr, "woody: compressed data segment size overflow\n");
        goto fail;
    }
    if (data_size == 0)
        data_size = WOODY_PAGE_SIZE;

    new_phnum = old_phnum + 2U + (pt_phdr_count == 0 ? 1U : 0U);
    if (new_phnum > UINT16_MAX)
    {
        fprintf(stderr, "woody: compressed ELF program-header count overflow\n");
        goto fail;
    }
    phdr_bytes = new_phnum * sizeof(Elf64_Phdr);
    if (align_up_u64(phdr_bytes, 16U, &stub_offset) < 0
        || align_up_u64(compact_size, WOODY_PAGE_SIZE, &new_offset) < 0
        || align_up_u64(max_vaddr_end, WOODY_PAGE_SIZE, &new_vaddr) < 0)
    {
        fprintf(stderr, "woody: compressed ELF layout overflow\n");
        goto fail;
    }
    if (exec_count - 1U > (UINT64_MAX - WOODY_STUB_SIZE) / WOODY_SEGMENT_DESC_SIZE)
    {
        fprintf(stderr, "woody: compressed segment descriptor table overflow\n");
        goto fail;
    }
    stub_total_size = WOODY_STUB_SIZE
        + (uint64_t)(exec_count - 1U) * WOODY_SEGMENT_DESC_SIZE;
    if (stub_offset > UINT64_MAX - stub_total_size)
    {
        fprintf(stderr, "woody: compressed stub size overflow\n");
        goto fail;
    }
    code_segment_size = stub_offset + stub_total_size;
    if (new_offset > UINT64_MAX - code_segment_size
        || new_vaddr > UINT64_MAX - code_segment_size
        || align_up_u64(new_offset + code_segment_size, WOODY_PAGE_SIZE, &data_offset) < 0
        || align_up_u64(new_vaddr + code_segment_size, WOODY_PAGE_SIZE, &data_vaddr) < 0
        || data_offset > UINT64_MAX - data_size
        || data_vaddr > UINT64_MAX - data_size)
    {
        fprintf(stderr, "woody: compressed code/data segment layout overflow\n");
        goto fail;
    }
    total_size = data_offset + data_size;
    stub_vaddr = new_vaddr + stub_offset;
    if (total_size > SIZE_MAX || total_size > (uint64_t)INT64_MAX
        || stub_vaddr > UINT64_MAX - STUB_JUMP_DISP_OFFSET - 4U)
    {
        fprintf(stderr, "woody: compressed output exceeds supported file/address limits\n");
        goto fail;
    }

    for (i = 0; i < old_phnum; i++)
    {
        if (phdr[i].p_type != PT_LOAD || (phdr[i].p_flags & PF_X))
            continue;
        shift = 0;
        old_offset = phdr[i].p_offset;
        for (j = 0; j < exec_count; j++)
        {
            if (old_offset >= remove_starts[j] + remove_lengths[j])
                shift += remove_lengths[j];
            else if (old_offset > remove_starts[j]
                && old_offset < remove_starts[j] + remove_lengths[j])
            {
                fprintf(stderr, "woody: a non-executable PT_LOAD starts inside a removed range\n");
                goto fail;
            }
        }
        rebased_offset = old_offset - shift;
        if (phdr[i].p_align > 1U
            && (phdr[i].p_vaddr % phdr[i].p_align)
                != (rebased_offset % phdr[i].p_align))
        {
            fprintf(stderr, "woody: compaction would violate a non-executable PT_LOAD alignment\n");
            goto fail;
        }
    }

    result = (unsigned char *)malloc((size_t)total_size);
    if (result == NULL)
    {
        perror("malloc compressed output");
        goto fail;
    }
    zero_bytes(result, (size_t)total_size);
    copy_src = 0;
    copy_dst = 0;
    for (i = 0; i < exec_count; i++)
    {
        uint64_t start = remove_starts[i];
        uint64_t end = start + remove_lengths[i];
        if (start < copy_src || end > input_size)
        {
            fprintf(stderr, "woody: invalid compaction range\n");
            goto fail;
        }
        if (start > copy_src)
        {
            copy_bytes(result + (size_t)copy_dst, input + (size_t)copy_src,
                (size_t)(start - copy_src));
            copy_dst += start - copy_src;
        }
        copy_src = end;
    }
    if (copy_src < input_size)
    {
        copy_bytes(result + (size_t)copy_dst, input + (size_t)copy_src,
            input_size - (size_t)copy_src);
        copy_dst += input_size - copy_src;
    }
    if (copy_dst != compact_size)
    {
        fprintf(stderr, "woody: compacted ELF size mismatch\n");
        goto fail;
    }
    copy_bytes(result, input, sizeof(Elf64_Ehdr));
    out_ehdr = (Elf64_Ehdr *)result;
    out_phdr = (Elf64_Phdr *)(result + (size_t)new_offset);

    if (pt_phdr_count == 0)
    {
        copy_bytes((unsigned char *)&out_phdr[1], (const unsigned char *)phdr,
            old_phnum * sizeof(Elf64_Phdr));
        zero_bytes((unsigned char *)&new_phdr, sizeof(new_phdr));
        new_phdr.p_type = PT_PHDR;
        new_phdr.p_flags = PF_R;
        new_phdr.p_offset = new_offset;
        new_phdr.p_vaddr = new_vaddr;
        new_phdr.p_paddr = new_vaddr;
        new_phdr.p_filesz = phdr_bytes;
        new_phdr.p_memsz = phdr_bytes;
        new_phdr.p_align = 8;
        copy_bytes((unsigned char *)&out_phdr[0],
            (const unsigned char *)&new_phdr, sizeof(new_phdr));
    }
    else
        copy_bytes((unsigned char *)out_phdr, (const unsigned char *)phdr,
            old_phnum * sizeof(Elf64_Phdr));

    for (i = 0; i < old_phnum; i++)
    {
        is_exec = 0;
        for (j = 0; j < exec_count; j++)
        {
            if (items[j].index == i)
            {
                is_exec = 1;
                break;
            }
        }
        if (is_exec)
        {
            out_phdr[pt_phdr_count == 0 ? i + 1U : i].p_filesz = 1U;
            out_phdr[pt_phdr_count == 0 ? i + 1U : i].p_offset =
                data_offset + (phdr[i].p_vaddr & (WOODY_PAGE_SIZE - 1U));
            out_phdr[pt_phdr_count == 0 ? i + 1U : i].p_align = WOODY_PAGE_SIZE;
        }
        else if (phdr[i].p_type != PT_PHDR && phdr[i].p_type != PT_NULL)
        {
            shift = 0;
            old_offset = phdr[i].p_offset;
            for (j = 0; j < exec_count; j++)
            {
                if (old_offset >= remove_starts[j] + remove_lengths[j])
                    shift += remove_lengths[j];
                else if (old_offset > remove_starts[j]
                    && old_offset < remove_starts[j] + remove_lengths[j])
                {
                    if (phdr[i].p_filesz != 0)
                    {
                        fprintf(stderr, "woody: a program header points into a removed range\n");
                        goto fail;
                    }
                    old_offset = remove_starts[j];
                    break;
                }
            }
            rebased_offset = old_offset - shift;
            out_phdr[pt_phdr_count == 0 ? i + 1U : i].p_offset = rebased_offset;
        }
        else if (phdr[i].p_type == PT_PHDR)
        {
            // upated apres dans le code
        }
    }
    if (pt_phdr_count != 0)
    {
        for (i = 0; i < old_phnum; i++)
        {
            if (out_phdr[i].p_type == PT_PHDR)
            {
                out_phdr[i].p_flags = PF_R;
                out_phdr[i].p_offset = new_offset;
                out_phdr[i].p_vaddr = new_vaddr;
                out_phdr[i].p_paddr = new_vaddr;
                out_phdr[i].p_filesz = phdr_bytes;
                out_phdr[i].p_memsz = phdr_bytes;
                out_phdr[i].p_align = 8;
            }
        }
    }
    zero_bytes((unsigned char *)&new_code_load, sizeof(new_code_load));
    new_code_load.p_type = PT_LOAD;
    new_code_load.p_flags = PF_R | PF_X;
    new_code_load.p_offset = new_offset;
    new_code_load.p_vaddr = new_vaddr;
    new_code_load.p_paddr = new_vaddr;
    new_code_load.p_filesz = code_segment_size;
    new_code_load.p_memsz = code_segment_size;
    new_code_load.p_align = WOODY_PAGE_SIZE;
    code_index = (size_t)(new_phnum - 2U);
    data_index = (size_t)(new_phnum - 1U);
    copy_bytes((unsigned char *)&out_phdr[code_index],
        (const unsigned char *)&new_code_load, sizeof(new_code_load));

    zero_bytes((unsigned char *)&new_data_load, sizeof(new_data_load));
    new_data_load.p_type = PT_LOAD;
    new_data_load.p_flags = PF_R | PF_W;
    new_data_load.p_offset = data_offset;
    new_data_load.p_vaddr = data_vaddr;
    new_data_load.p_paddr = data_vaddr;
    new_data_load.p_filesz = data_size;
    new_data_load.p_memsz = data_size;
    new_data_load.p_align = WOODY_PAGE_SIZE;
    copy_bytes((unsigned char *)&out_phdr[data_index],
        (const unsigned char *)&new_data_load, sizeof(new_data_load));

    stub = result + (size_t)new_offset + (size_t)stub_offset;
    copy_bytes(stub, g_woody_stub, WOODY_STUB_SIZE);
    if (stub_vaddr >= UINT64_MAX - STUB_JUMP_DISP_OFFSET - 4U)
    {
        fprintf(stderr, "woody: compressed stub jump address overflow\n");
        goto fail;
    }
    jump_next = stub_vaddr + STUB_JUMP_DISP_OFFSET + 4U;
    if (ehdr->e_entry >= jump_next)
    {
        if (ehdr->e_entry - jump_next > INT32_MAX)
        {
            fprintf(stderr, "woody: original entry point is outside compressed stub rel32 range\n");
            goto fail;
        }
        jump_delta = (int64_t)(ehdr->e_entry - jump_next);
    }
    else
    {
        if (jump_next - ehdr->e_entry > (uint64_t)INT32_MAX + 1U)
        {
            fprintf(stderr, "woody: original entry point is outside compressed stub rel32 range\n");
            goto fail;
        }
        jump_delta = -(int64_t)(jump_next - ehdr->e_entry);
    }
    write_u32_le(stub + STUB_JUMP_DISP_OFFSET, (uint32_t)(int32_t)jump_delta);
    write_u64_le(stub + STUB_SEGMENT_COUNT_OFFSET, exec_count);
    for (i = 0; i < WOODY_KEY_SIZE; i++)
        stub[STUB_KEY_OFFSET + i] = key_bytes[i];

    for (i = 0; i < WOODY_KEY_SIZE / 4U; i++)
        key_words[i] = read_u32_le(key_bytes + i * 4U);
    counter_offset = 0;
    for (i = 0; i < exec_count; i++)
    {
        const Elf64_Phdr *p = &phdr[items[i].index];
        size_t phdr_index = pt_phdr_count == 0 ? items[i].index + 1U : items[i].index;
        uint64_t src_vaddr = data_vaddr + items[i].payload_offset;

        blocks = items[i].payload_length / 8U
            + (items[i].payload_length % 8U != 0 ? 1U : 0U);
        items[i].nonce = nonce + counter_offset;
        record = stub + STUB_SEGMENT_TABLE_OFFSET + i * WOODY_SEGMENT_DESC_SIZE;
        write_u64_le(record, p->p_vaddr - stub_vaddr);
        write_u64_le(record + 8U, src_vaddr - stub_vaddr);
        write_u64_le(record + 16U, items[i].payload_length);
        write_u64_le(record + 24U, p->p_filesz);
        write_u64_le(record + 32U, items[i].nonce);
        write_u32_le(record + 40U, elf_flags_to_prot(p->p_flags));
        write_u32_le(record + 44U, 0U);
        write_u32_le(record + 48U, items[i].flags);
        write_u32_le(record + 52U, 0U);

        copy_bytes(result + (size_t)data_offset + (size_t)items[i].payload_offset,
            items[i].payload, items[i].payload_length);
        woody_xtea_ctr_asm(result + (size_t)data_offset + (size_t)items[i].payload_offset,
            items[i].payload_length, key_words, items[i].nonce);
        write_u32_le(record + 44U,
            woody_crc32(result + (size_t)data_offset + (size_t)items[i].payload_offset,
                items[i].payload_length));
        counter_offset += blocks;
        (void)phdr_index;
    }

    out_ehdr->e_entry = stub_vaddr;
    out_ehdr->e_phoff = new_offset;
    out_ehdr->e_phnum = (Elf64_Half)new_phnum;
    out_ehdr->e_shoff = 0;
    out_ehdr->e_shentsize = 0;
    out_ehdr->e_shnum = 0;
    out_ehdr->e_shstrndx = SHN_UNDEF;
    fprintf(stdout, "compression: %llu executable bytes -> %llu stored payload bytes\n",
        (unsigned long long)original_payload_total,
        (unsigned long long)payload_cursor);
    free_compressed_segments(items, exec_count);
    free(remove_starts);
    free(remove_lengths);
    *output = result;
    *output_size = (size_t)total_size;
    return (0);

fail:
    free(result);
    free_compressed_segments(items, exec_count);
    free(remove_starts);
    free(remove_lengths);
    return (-1);
}

int woody_pack_elf(const unsigned char *input, size_t input_size,
        unsigned char **output, size_t *output_size,
        const unsigned char key_bytes[WOODY_KEY_SIZE], uint64_t nonce,
        int compress_payloads)
{
    const Elf64_Ehdr  *source_ehdr;
    const Elf64_Phdr  *source_phdr;
    Elf64_Ehdr        *out_ehdr;
    Elf64_Phdr        *out_phdr;
    Elf64_Phdr        new_load;
    Elf64_Phdr        new_phdr;
    unsigned char     *result;
    unsigned char     *stub;
    unsigned char     *record;
    size_t            *exec_indices;
    uint32_t          key_words[4];
    uint64_t          max_vaddr_end;
    uint64_t          new_vaddr;
    uint64_t          new_offset;
    uint64_t          new_phnum;
    uint64_t          phdr_bytes;
    uint64_t          stub_offset;
    uint64_t          stub_total_size;
    uint64_t          segment_size;
    uint64_t          total_size;
    uint64_t          stub_vaddr;
    uint64_t          counter_offset;
    uint64_t          blocks;
    size_t            exec_count;
    size_t            old_phnum;
    size_t            pt_phdr_count;
    size_t            i;

    *output = NULL;
    *output_size = 0;
    exec_indices = NULL;
    if (validate_elf(input, input_size, &source_ehdr, &source_phdr,
            &exec_indices, &exec_count, &max_vaddr_end, &pt_phdr_count) < 0)
        return (-1);
    old_phnum = source_ehdr->e_phnum;
    if (check_executable_pages_isolated(source_phdr, old_phnum, input_size,
            exec_indices, exec_count) < 0)
    {
        free(exec_indices);
        return (-1);
    }
    if (compress_payloads)
    {
        int compressed_result;

        compressed_result = pack_elf_compressed(input, input_size, output,
                output_size, key_bytes, nonce, source_ehdr, source_phdr,
                exec_indices, exec_count, max_vaddr_end, pt_phdr_count);
        free(exec_indices);
        return (compressed_result);
    }
    new_phnum = old_phnum + 1U + (pt_phdr_count == 0 ? 1U : 0U);
    if (new_phnum > UINT16_MAX)
    {
        free(exec_indices);
        return (fprintf(stderr, "woody: program-header count would overflow ELF64 metadata\n"), -1);
    }
    phdr_bytes = new_phnum * sizeof(Elf64_Phdr);
    if (align_up_u64(phdr_bytes, 16U, &stub_offset) < 0
        || align_up_u64(max_vaddr_end, WOODY_PAGE_SIZE, &new_vaddr) < 0
        || align_up_u64((uint64_t)input_size, WOODY_PAGE_SIZE, &new_offset) < 0)
    {
        free(exec_indices);
        return (fprintf(stderr, "woody: output layout overflow\n"), -1);
    }
    if (exec_count - 1U > (UINT64_MAX - WOODY_STUB_SIZE) / WOODY_SEGMENT_DESC_SIZE)
    {
        free(exec_indices);
        return (fprintf(stderr, "woody: segment descriptor table size overflows\n"), -1);
    }
    stub_total_size = WOODY_STUB_SIZE
        + (uint64_t)(exec_count - 1U) * WOODY_SEGMENT_DESC_SIZE;
    if (stub_offset > UINT64_MAX - stub_total_size)
    {
        free(exec_indices);
        return (fprintf(stderr, "woody: stub size overflow\n"), -1);
    }
    segment_size = stub_offset + stub_total_size;
    if (new_offset > UINT64_MAX - segment_size)
    {
        free(exec_indices);
        return (fprintf(stderr, "woody: output file size overflow\n"), -1);
    }
    total_size = new_offset + segment_size;
    if (total_size > SIZE_MAX || total_size > (uint64_t)INT64_MAX
        || new_vaddr > UINT64_MAX - segment_size)
    {
        free(exec_indices);
        return (fprintf(stderr, "woody: packed output is too large\n"), -1);
    }
    stub_vaddr = new_vaddr + stub_offset;
    if (stub_vaddr > UINT64_MAX - STUB_JUMP_DISP_OFFSET - 4U)
    {
        free(exec_indices);
        return (fprintf(stderr, "woody: stub virtual address overflows\n"), -1);
    }

    result = (unsigned char *)malloc((size_t)total_size);
    if (result == NULL)
    {
        free(exec_indices);
        return (perror("malloc"), -1);
    }
    zero_bytes(result, (size_t)total_size);
    copy_bytes(result, input, input_size);
    out_ehdr = (Elf64_Ehdr *)result;
    out_phdr = (Elf64_Phdr *)(result + new_offset);
    if (pt_phdr_count == 0)
    {
        copy_bytes((unsigned char *)&out_phdr[1],
            (const unsigned char *)source_phdr,
            old_phnum * sizeof(Elf64_Phdr));
        zero_bytes((unsigned char *)&new_phdr, sizeof(new_phdr));
        new_phdr.p_type = PT_PHDR;
        new_phdr.p_flags = PF_R;
        new_phdr.p_offset = new_offset;
        new_phdr.p_vaddr = new_vaddr;
        new_phdr.p_paddr = new_vaddr;
        new_phdr.p_filesz = phdr_bytes;
        new_phdr.p_memsz = phdr_bytes;
        new_phdr.p_align = 8;
        copy_bytes((unsigned char *)&out_phdr[0],
            (const unsigned char *)&new_phdr, sizeof(new_phdr));
    }
    else
    {
        copy_bytes((unsigned char *)out_phdr,
            (const unsigned char *)source_phdr,
            old_phnum * sizeof(Elf64_Phdr));
        i = 0;
        while (i < old_phnum)
        {
            if (out_phdr[i].p_type == PT_PHDR)
            {
                out_phdr[i].p_flags = PF_R;
                out_phdr[i].p_offset = new_offset;
                out_phdr[i].p_vaddr = new_vaddr;
                out_phdr[i].p_paddr = new_vaddr;
                out_phdr[i].p_filesz = phdr_bytes;
                out_phdr[i].p_memsz = phdr_bytes;
                out_phdr[i].p_align = 8;
            }
            i++;
        }
    }
    zero_bytes((unsigned char *)&new_load, sizeof(new_load));
    new_load.p_type = PT_LOAD;
    new_load.p_flags = PF_R | PF_X;
    new_load.p_offset = new_offset;
    new_load.p_vaddr = new_vaddr;
    new_load.p_paddr = new_vaddr;
    new_load.p_filesz = segment_size;
    new_load.p_memsz = segment_size;
    new_load.p_align = WOODY_PAGE_SIZE;
    copy_bytes((unsigned char *)&out_phdr[new_phnum - 1U],
        (const unsigned char *)&new_load, sizeof(new_load));

    stub = result + new_offset + stub_offset;
    copy_bytes(stub, g_woody_stub, WOODY_STUB_SIZE);
    if (patch_stub(stub, stub_vaddr, source_ehdr, source_phdr,
            exec_indices, exec_count, key_bytes, nonce) < 0)
    {
        free(exec_indices);
        free(result);
        return (-1);
    }
    i = 0;
    while (i < WOODY_KEY_SIZE / 4U)
    {
        key_words[i] = read_u32_le(key_bytes + i * 4U);
        i++;
    }
    counter_offset = 0;
    i = 0;
    while (i < exec_count)
    {
        size_t exec_index;
        uint64_t segment_nonce;

        exec_index = exec_indices[i];
        segment_nonce = nonce + counter_offset;
        record = stub + STUB_SEGMENT_TABLE_OFFSET
            + i * WOODY_SEGMENT_DESC_SIZE;
        write_u64_le(record + 32U, segment_nonce);
        woody_xtea_ctr_asm(result + source_phdr[exec_index].p_offset,
            (size_t)source_phdr[exec_index].p_filesz, key_words, segment_nonce);
        write_u32_le(record + 44U,
            woody_crc32(result + source_phdr[exec_index].p_offset,
                (size_t)source_phdr[exec_index].p_filesz));
        blocks = source_phdr[exec_index].p_filesz / 8U
            + (source_phdr[exec_index].p_filesz % 8U != 0 ? 1U : 0U);
        counter_offset += blocks;
        i++;
    }
    out_ehdr->e_entry = stub_vaddr;
    out_ehdr->e_phoff = new_offset;
    out_ehdr->e_phnum = (Elf64_Half)new_phnum;
    free(exec_indices);
    *output = result;
    *output_size = (size_t)total_size;
    return (0);
}
