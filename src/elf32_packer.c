#include "woody.h"
#include "woody_stub32_blob.h"

#define WOODY32_DESC_SIZE 24U

static void copy32(unsigned char *dst, const unsigned char *src, size_t size)
{
    size_t i = 0;
    while (i < size)
    {
        dst[i] = src[i];
        i++;
    }
}

static void zero32(unsigned char *dst, size_t size)
{
    size_t i = 0;
    while (i < size)
    {
        dst[i] = 0;
        i++;
    }
}

static void put32(unsigned char *dst, uint32_t value)
{
    dst[0] = (unsigned char)value;
    dst[1] = (unsigned char)(value >> 8);
    dst[2] = (unsigned char)(value >> 16);
    dst[3] = (unsigned char)(value >> 24);
}

static void put64_32(unsigned char *dst, uint64_t value)
{
    put32(dst, (uint32_t)value);
    put32(dst + 4, (uint32_t)(value >> 32));
}

static int power_two32(uint32_t value)
{
    return (value != 0U && (value & (value - 1U)) == 0U);
}

static int align_up32(uint64_t value, uint64_t alignment, uint64_t *result)
{
    uint64_t add;

    if (alignment == 0 || (alignment & (alignment - 1U)) != 0)
        return (-1);
    add = (alignment - (value & (alignment - 1U))) & (alignment - 1U);
    if (value > UINT64_MAX - add)
        return (-1);
    *result = value + add;
    return (0);
}

static uint64_t align_down32(uint64_t value, uint64_t alignment)
{
    return (value & ~(alignment - 1U));
}

static int inside32(uint64_t offset, uint64_t length, size_t total)
{
    return (offset <= (uint64_t)total && length <= (uint64_t)total - offset);
}

static uint32_t prot32(uint32_t flags)
{
    uint32_t prot = 0;
    if (flags & PF_R)
        prot |= PROT_READ;
    if (flags & PF_W)
        prot |= PROT_WRITE;
    if (flags & PF_X)
        prot |= PROT_EXEC;
    return (prot);
}

static int validate_elf32(const unsigned char *input, size_t input_size,
        const Elf32_Ehdr **ehdr_out, const Elf32_Phdr **phdr_out,
        size_t **exec_indices_out, size_t *exec_count_out,
        uint64_t *max_vaddr_end_out, size_t *pt_phdr_count_out)
{
    const Elf32_Ehdr *ehdr;
    const Elf32_Phdr *phdr;
    size_t *exec_indices;
    size_t i, exec_count, phdr_count, interp_count, dynamic_count;
    size_t phdr_index, interp_index, first_load;
    uint64_t end;
    int entry_found;

    *exec_indices_out = NULL;
    *exec_count_out = 0;
    if (input_size < sizeof(Elf32_Ehdr))
        return (fprintf(stderr, "woody: file is smaller than an ELF32 header\n"), -1);
    ehdr = (const Elf32_Ehdr *)input;
    if (ehdr->e_ident[EI_MAG0] != ELFMAG0 || ehdr->e_ident[EI_MAG1] != ELFMAG1
        || ehdr->e_ident[EI_MAG2] != ELFMAG2 || ehdr->e_ident[EI_MAG3] != ELFMAG3)
        return (fprintf(stderr, "woody: input is not an ELF file\n"), -1);
    if (ehdr->e_ident[EI_CLASS] != ELFCLASS32 || ehdr->e_ident[EI_DATA] != ELFDATA2LSB
        || ehdr->e_machine != EM_386)
        return (fprintf(stderr, "woody: unsupported architecture; ELF32 i386 required\n"), -1);
    if (ehdr->e_ident[EI_VERSION] != EV_CURRENT || ehdr->e_version != EV_CURRENT
        || ehdr->e_ehsize != sizeof(Elf32_Ehdr)
        || ehdr->e_phentsize != sizeof(Elf32_Phdr))
        return (fprintf(stderr, "woody: malformed or unsupported ELF32 header\n"), -1);
    if (ehdr->e_type != ET_EXEC && ehdr->e_type != ET_DYN)
        return (fprintf(stderr, "woody: only ELF32 ET_EXEC and ET_DYN are supported\n"), -1);
    if (ehdr->e_phnum == 0 || ehdr->e_phnum == PN_XNUM
        || ehdr->e_phoff % 4U != 0
        || !inside32(ehdr->e_phoff, (uint64_t)ehdr->e_phnum * sizeof(Elf32_Phdr), input_size))
        return (fprintf(stderr, "woody: invalid or extended ELF32 program-header table\n"), -1);

    phdr = (const Elf32_Phdr *)(input + ehdr->e_phoff);
    exec_indices = (size_t *)malloc((size_t)ehdr->e_phnum * sizeof(size_t));
    if (exec_indices == NULL)
        return (perror("malloc"), -1);
    exec_count = phdr_count = interp_count = dynamic_count = 0;
    phdr_index = interp_index = first_load = SIZE_MAX;
    *max_vaddr_end_out = 0;
    entry_found = 0;
    i = 0;
    while (i < ehdr->e_phnum)
    {
        if (phdr[i].p_type == PT_PHDR)
        {
            phdr_count++;
            phdr_index = i;
        }
        else if (phdr[i].p_type == PT_INTERP)
        {
            interp_count++;
            interp_index = i;
            if (phdr[i].p_filesz < 2U
                || !inside32(phdr[i].p_offset, phdr[i].p_filesz, input_size)
                || input[phdr[i].p_offset + phdr[i].p_filesz - 1U] != 0)
            {
                free(exec_indices);
                return (fprintf(stderr, "woody: malformed ELF32 PT_INTERP\n"), -1);
            }
        }
        else if (phdr[i].p_type == PT_DYNAMIC)
        {
            dynamic_count++;
            if (phdr[i].p_filesz > phdr[i].p_memsz
                || phdr[i].p_filesz % sizeof(Elf32_Dyn) != 0
                || !inside32(phdr[i].p_offset, phdr[i].p_filesz, input_size))
            {
                free(exec_indices);
                return (fprintf(stderr, "woody: malformed ELF32 PT_DYNAMIC\n"), -1);
            }
        }
        if (phdr[i].p_type == PT_LOAD)
        {
            if (first_load == SIZE_MAX)
                first_load = i;
            if (phdr[i].p_filesz > phdr[i].p_memsz
                || !inside32(phdr[i].p_offset, phdr[i].p_filesz, input_size)
                || (uint64_t)phdr[i].p_vaddr + phdr[i].p_memsz > UINT32_MAX)
            {
                free(exec_indices);
                return (fprintf(stderr, "woody: invalid ELF32 PT_LOAD range\n"), -1);
            }
            if (phdr[i].p_align > 1U
                && (!power_two32(phdr[i].p_align)
                    || phdr[i].p_vaddr % phdr[i].p_align != phdr[i].p_offset % phdr[i].p_align))
            {
                free(exec_indices);
                return (fprintf(stderr, "woody: invalid ELF32 PT_LOAD alignment\n"), -1);
            }
            if ((phdr[i].p_vaddr & (WOODY_PAGE_SIZE - 1U))
                != (phdr[i].p_offset & (WOODY_PAGE_SIZE - 1U)))
            {
                free(exec_indices);
                return (fprintf(stderr, "woody: ELF32 PT_LOAD violates page congruence\n"), -1);
            }
            end = (uint64_t)phdr[i].p_vaddr + phdr[i].p_memsz;
            if (end > *max_vaddr_end_out)
                *max_vaddr_end_out = end;
            if ((phdr[i].p_flags & PF_X) && phdr[i].p_filesz > 0U)
            {
                exec_indices[exec_count++] = i;
                if (ehdr->e_entry >= phdr[i].p_vaddr
                    && (uint64_t)ehdr->e_entry - phdr[i].p_vaddr < phdr[i].p_filesz)
                    entry_found++;
            }
        }
        i++;
    }
    if (phdr_count > 1U || interp_count > 1U || dynamic_count > 1U
        || (phdr_count == 1U && phdr_index > first_load)
        || (interp_count == 1U && interp_index > first_load))
    {
        free(exec_indices);
        return (fprintf(stderr, "woody: duplicate or misplaced ELF32 program headers\n"), -1);
    }
    if (exec_count == 0U || entry_found != 1)
    {
        free(exec_indices);
        return (fprintf(stderr, "woody: ELF32 entry must belong to one executable PT_LOAD\n"), -1);
    }
    *ehdr_out = ehdr;
    *phdr_out = phdr;
    *exec_indices_out = exec_indices;
    *exec_count_out = exec_count;
    *pt_phdr_count_out = phdr_count;
    return (0);
}

static int check_exec_ranges32(const Elf32_Phdr *phdr, size_t phnum,
        size_t input_size, const size_t *exec_indices, size_t exec_count)
{
    uint64_t begin, end, other_begin, other_end, file_end, other_file_end;
    size_t i, j, target;

    for (i = 0; i < exec_count; i++)
    {
        target = exec_indices[i];
        begin = align_down32(phdr[target].p_vaddr, WOODY_PAGE_SIZE);
        if (align_up32((uint64_t)phdr[target].p_vaddr + phdr[target].p_memsz,
                WOODY_PAGE_SIZE, &end) < 0)
            return (fprintf(stderr, "woody: ELF32 executable page range overflow\n"), -1);
        file_end = (uint64_t)phdr[target].p_offset + phdr[target].p_filesz;
        for (j = 0; j < phnum; j++)
        {
            if (j != target && phdr[j].p_type != PT_NULL && phdr[j].p_filesz > 0U)
            {
                if (!inside32(phdr[j].p_offset, phdr[j].p_filesz, input_size))
                    return (fprintf(stderr, "woody: ELF32 program-header file range invalid\n"), -1);
                other_file_end = (uint64_t)phdr[j].p_offset + phdr[j].p_filesz;
                if (phdr[target].p_offset < other_file_end
                    && phdr[j].p_offset < file_end)
                    return (fprintf(stderr, "woody: ELF32 executable file range aliases another segment\n"), -1);
            }
            if (j != target && phdr[j].p_type == PT_LOAD && phdr[j].p_memsz > 0U)
            {
                other_begin = align_down32(phdr[j].p_vaddr, WOODY_PAGE_SIZE);
                if (align_up32((uint64_t)phdr[j].p_vaddr + phdr[j].p_memsz,
                        WOODY_PAGE_SIZE, &other_end) < 0)
                    return (fprintf(stderr, "woody: ELF32 PT_LOAD page range overflow\n"), -1);
                if (begin < other_end && other_begin < end)
                    return (fprintf(stderr, "woody: ELF32 executable PT_LOAD shares pages\n"), -1);
            }
#ifdef PT_GNU_RELRO
            if (phdr[j].p_type == PT_GNU_RELRO && phdr[j].p_memsz > 0U)
            {
                other_begin = align_down32(phdr[j].p_vaddr, WOODY_PAGE_SIZE);
                if (align_up32((uint64_t)phdr[j].p_vaddr + phdr[j].p_memsz,
                        WOODY_PAGE_SIZE, &other_end) < 0)
                    return (fprintf(stderr, "woody: ELF32 RELRO range overflow\n"), -1);
                if (begin < other_end && other_begin < end)
                    return (fprintf(stderr, "woody: ELF32 executable PT_LOAD overlaps RELRO\n"), -1);
            }
#endif
        }
    }
    return (0);
}

int woody_pack_elf32(const unsigned char *input, size_t input_size,
        unsigned char **output, size_t *output_size,
        const unsigned char key_bytes[WOODY_KEY_SIZE], uint64_t nonce)
{
    const Elf32_Ehdr *src_ehdr;
    const Elf32_Phdr *src_phdr;
    Elf32_Ehdr *dst_ehdr;
    Elf32_Phdr *dst_phdr;
    Elf32_Phdr add_load, add_phdr;
    unsigned char *result, *stub, *record;
    size_t *exec_indices;
    size_t exec_count, old_phnum, phdr_count, i;
    uint64_t max_vaddr_end, new_vaddr, new_offset, new_phnum;
    uint64_t phdr_bytes, stub_offset, stub_size, segment_size, total_size, stub_vaddr;
    uint64_t counter_offset, blocks, total_blocks, seg_nonce;
    uint32_t key_words[4];

    *output = NULL;
    *output_size = 0;
    exec_indices = NULL;
    if (validate_elf32(input, input_size, &src_ehdr, &src_phdr,
            &exec_indices, &exec_count, &max_vaddr_end, &phdr_count) < 0)
        return (-1);
    old_phnum = src_ehdr->e_phnum;
    if (check_exec_ranges32(src_phdr, old_phnum, input_size, exec_indices, exec_count) < 0)
    {
        free(exec_indices);
        return (-1);
    }
    new_phnum = old_phnum + 1U + (phdr_count == 0U ? 1U : 0U);
    if (new_phnum > UINT16_MAX)
    {
        free(exec_indices);
        return (fprintf(stderr, "woody: ELF32 program-header count overflow\n"), -1);
    }
    phdr_bytes = new_phnum * sizeof(Elf32_Phdr);
    if (align_up32(phdr_bytes, 16U, &stub_offset) < 0
        || align_up32(max_vaddr_end, WOODY_PAGE_SIZE, &new_vaddr) < 0
        || align_up32(input_size, WOODY_PAGE_SIZE, &new_offset) < 0)
    {
        free(exec_indices);
        return (fprintf(stderr, "woody: ELF32 output layout overflow\n"), -1);
    }
    if (exec_count - 1U > (UINT64_MAX - WOODY32_STUB_SIZE) / WOODY32_DESC_SIZE)
    {
        free(exec_indices);
        return (fprintf(stderr, "woody: ELF32 segment descriptor table overflow\n"), -1);
    }
    stub_size = WOODY32_STUB_SIZE + (exec_count - 1U) * WOODY32_DESC_SIZE;
    if (stub_offset > UINT64_MAX - stub_size)
    {
        free(exec_indices);
        return (fprintf(stderr, "woody: ELF32 stub size overflow\n"), -1);
    }
    segment_size = stub_offset + stub_size;
    if (new_offset > UINT64_MAX - segment_size)
    {
        free(exec_indices);
        return (fprintf(stderr, "woody: ELF32 output file size overflow\n"), -1);
    }
    total_size = new_offset + segment_size;
    if (new_vaddr > UINT32_MAX || new_offset > UINT32_MAX
        || total_size > UINT32_MAX || total_size > SIZE_MAX
        || new_vaddr + segment_size > UINT32_MAX)
    {
        free(exec_indices);
        return (fprintf(stderr, "woody: packed ELF32 would exceed 32-bit address/file limits\n"), -1);
    }
    stub_vaddr = new_vaddr + stub_offset;
    if (stub_vaddr > UINT32_MAX)
    {
        free(exec_indices);
        return (fprintf(stderr, "woody: ELF32 stub address overflow\n"), -1);
    }
    total_blocks = 0;
    for (i = 0; i < exec_count; i++)
    {
        const Elf32_Phdr *p = &src_phdr[exec_indices[i]];
        blocks = p->p_filesz / 8U + ((p->p_filesz % 8U) != 0U);
        if (total_blocks > UINT64_MAX - blocks)
        {
            free(exec_indices);
            return (fprintf(stderr, "woody: ELF32 CTR counter range overflow\n"), -1);
        }
        total_blocks += blocks;
    }
    if (total_blocks == 0U || nonce > UINT64_MAX - (total_blocks - 1U))
    {
        free(exec_indices);
        return (fprintf(stderr, "woody: ELF32 nonce range would overflow\n"), -1);
    }

    result = (unsigned char *)malloc((size_t)total_size);
    if (result == NULL)
    {
        free(exec_indices);
        return (perror("malloc"), -1);
    }
    zero32(result, (size_t)total_size);
    copy32(result, input, input_size);
    dst_ehdr = (Elf32_Ehdr *)result;
    dst_phdr = (Elf32_Phdr *)(result + (size_t)new_offset);
    if (phdr_count == 0U)
    {
        copy32((unsigned char *)&dst_phdr[1], (const unsigned char *)src_phdr,
            old_phnum * sizeof(Elf32_Phdr));
        zero32((unsigned char *)&add_phdr, sizeof(add_phdr));
        add_phdr.p_type = PT_PHDR;
        add_phdr.p_flags = PF_R;
        add_phdr.p_offset = (Elf32_Off)new_offset;
        add_phdr.p_vaddr = (Elf32_Addr)new_vaddr;
        add_phdr.p_paddr = (Elf32_Addr)new_vaddr;
        add_phdr.p_filesz = (Elf32_Word)phdr_bytes;
        add_phdr.p_memsz = (Elf32_Word)phdr_bytes;
        add_phdr.p_align = 4U;
        copy32((unsigned char *)&dst_phdr[0], (const unsigned char *)&add_phdr,
            sizeof(add_phdr));
    }
    else
    {
        copy32((unsigned char *)dst_phdr, (const unsigned char *)src_phdr,
            old_phnum * sizeof(Elf32_Phdr));
        for (i = 0; i < old_phnum; i++)
        {
            if (dst_phdr[i].p_type == PT_PHDR)
            {
                dst_phdr[i].p_flags = PF_R;
                dst_phdr[i].p_offset = (Elf32_Off)new_offset;
                dst_phdr[i].p_vaddr = (Elf32_Addr)new_vaddr;
                dst_phdr[i].p_paddr = (Elf32_Addr)new_vaddr;
                dst_phdr[i].p_filesz = (Elf32_Word)phdr_bytes;
                dst_phdr[i].p_memsz = (Elf32_Word)phdr_bytes;
                dst_phdr[i].p_align = 4U;
            }
        }
    }
    zero32((unsigned char *)&add_load, sizeof(add_load));
    add_load.p_type = PT_LOAD;
    add_load.p_flags = PF_R | PF_X;
    add_load.p_offset = (Elf32_Off)new_offset;
    add_load.p_vaddr = (Elf32_Addr)new_vaddr;
    add_load.p_paddr = (Elf32_Addr)new_vaddr;
    add_load.p_filesz = (Elf32_Word)segment_size;
    add_load.p_memsz = (Elf32_Word)segment_size;
    add_load.p_align = (Elf32_Word)WOODY_PAGE_SIZE;
    copy32((unsigned char *)&dst_phdr[new_phnum - 1U],
        (const unsigned char *)&add_load, sizeof(add_load));

    stub = result + (size_t)new_offset + (size_t)stub_offset;
    copy32(stub, g_woody_stub32, WOODY32_STUB_SIZE);
    put32(stub + STUB32_SEGMENT_COUNT_OFFSET, (uint32_t)exec_count);
    for (i = 0; i < WOODY_KEY_SIZE; i++)
        stub[STUB32_KEY_OFFSET + i] = key_bytes[i];
    put32(stub + STUB32_JUMP_DISP_OFFSET,
        (uint32_t)(src_ehdr->e_entry - ((uint32_t)stub_vaddr
            + (uint32_t)STUB32_JUMP_DISP_OFFSET + 4U)));

    for (i = 0; i < WOODY_KEY_SIZE / 4U; i++)
    {
        key_words[i] = (uint32_t)key_bytes[i * 4U]
            | ((uint32_t)key_bytes[i * 4U + 1U] << 8)
            | ((uint32_t)key_bytes[i * 4U + 2U] << 16)
            | ((uint32_t)key_bytes[i * 4U + 3U] << 24);
    }
    counter_offset = 0;
    for (i = 0; i < exec_count; i++)
    {
        const Elf32_Phdr *p = &src_phdr[exec_indices[i]];
        uint64_t dest_delta = (uint32_t)(p->p_vaddr - (uint32_t)stub_vaddr);
        record = stub + STUB32_SEGMENT_TABLE_OFFSET + i * WOODY32_DESC_SIZE;
        blocks = p->p_filesz / 8U + ((p->p_filesz % 8U) != 0U);
        seg_nonce = nonce + counter_offset;
        put32(record, (uint32_t)dest_delta);
        put32(record + 4U, p->p_filesz);
        put64_32(record + 8U, seg_nonce);
        put32(record + 16U, prot32(p->p_flags));
        put32(record + 20U, 0U);
        woody_xtea_ctr_asm(result + p->p_offset, p->p_filesz, key_words, seg_nonce);
        put32(record + 20U, woody_crc32(result + p->p_offset, p->p_filesz));
        counter_offset += blocks;
    }

    dst_ehdr->e_entry = (Elf32_Addr)stub_vaddr;
    dst_ehdr->e_phoff = (Elf32_Off)new_offset;
    dst_ehdr->e_phnum = (Elf32_Half)new_phnum;
    free(exec_indices);
    *output = result;
    *output_size = (size_t)total_size;
    return (0);
}
