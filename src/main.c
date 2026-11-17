#include "woody.h"

static void print_usage(FILE *stream, const char *program)
{
    fprintf(stream,
        "Usage: %s [options] <ELF32-i386-or-ELF64-x86_64>\n"
        "Options:\n"
        "  -k, --key HEX       Use a 128-bit key (32 hexadecimal characters)\n"
        "      --key-file FILE Read the 128-bit key from FILE\n"
        "  -o, --output FILE   Write the packed executable to FILE (default: woody)\n"
        "      --compress      Compress executable payloads (ELF64 only)\n"
        "      --random-key    Generate a random key (default)\n"
        "  -h, --help          Display this help\n"
        "  --                  End option processing\n",
        program);
}

static int hex_value(unsigned char c)
{
    if (c >= '0' && c <= '9')
        return ((int)c - '0');
    if (c >= 'a' && c <= 'f')
        return ((int)c - 'a' + 10);
    if (c >= 'A' && c <= 'F')
        return ((int)c - 'A' + 10);
    return (-1);
}

static int parse_hex_key(const char *text, unsigned char key[WOODY_KEY_SIZE])
{
    size_t i;
    int high;
    int low;

    if (text == NULL || strlen(text) != WOODY_KEY_SIZE * 2U)
        return (-1);
    i = 0;
    while (i < WOODY_KEY_SIZE)
    {
        high = hex_value((unsigned char)text[i * 2U]);
        low = hex_value((unsigned char)text[i * 2U + 1U]);
        if (high < 0 || low < 0)
            return (-1);
        key[i] = (unsigned char)((high << 4) | low);
        i++;
    }
    return (0);
}

static int read_key_file(const char *path, unsigned char key[WOODY_KEY_SIZE])
{
    unsigned char contents[WOODY_KEY_SIZE * 2U + 3U];
    size_t done;
    ssize_t amount;
    int fd;
    size_t length;

    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return (perror(path), -1);
    done = 0;
    while (done < sizeof(contents))
    {
        amount = read(fd, contents + done, sizeof(contents) - done);
        if (amount < 0)
        {
            if (errno == EINTR)
                continue;
            perror("read key file");
            (void)close(fd);
            return (-1);
        }
        if (amount == 0)
            break;
        done += (size_t)amount;
    }
    if (close(fd) < 0)
        return (perror("close key file"), -1);
    length = done;
    if (length > 0 && contents[length - 1U] == '\n')
    {
        length--;
        if (length > 0 && contents[length - 1U] == '\r')
            length--;
    }
    if (length == WOODY_KEY_SIZE * 2U)
        contents[length] = '\0';
    if (length != WOODY_KEY_SIZE * 2U || parse_hex_key((const char *)contents, key) < 0)
    {
        fprintf(stderr,
            "woody: key file must contain exactly 32 hexadecimal characters "
            "with an optional final newline\n");
        return (-1);
    }
    return (0);
}

static int parse_arguments(int argc, char **argv, const char **input_path,
        const char **output_path, unsigned char key[WOODY_KEY_SIZE], int *has_key,
        int *compress_payloads)
{
    int i;
    int end_options;
    int key_source_seen;
    int output_seen;
    int compress_seen;

    *input_path = NULL;
    *output_path = WOODY_OUTPUT_NAME;
    *has_key = 0;
    *compress_payloads = 0;
    end_options = 0;
    key_source_seen = 0;
    output_seen = 0;
    compress_seen = 0;
    i = 1;
    while (i < argc)
    {
        if (!end_options && strcmp(argv[i], "--") == 0)
        {
            end_options = 1;
            i++;
            continue;
        }
        if (!end_options && (strcmp(argv[i], "-h") == 0
                || strcmp(argv[i], "--help") == 0))
        {
            print_usage(stdout, argv[0]);
            return (1);
        }
        if (!end_options && (strcmp(argv[i], "-k") == 0
                || strcmp(argv[i], "--key") == 0))
        {
            if (i + 1 >= argc || key_source_seen)
                return (fprintf(stderr, "woody: --key requires one key and may be specified only once\n"), -1);
            if (parse_hex_key(argv[i + 1], key) < 0)
                return (fprintf(stderr, "woody: key must be exactly 32 hexadecimal characters\n"), -1);
            *has_key = 1;
            key_source_seen = 1;
            i += 2;
            continue;
        }
        if (!end_options && strcmp(argv[i], "--key-file") == 0)
        {
            if (i + 1 >= argc || key_source_seen)
                return (fprintf(stderr, "woody: --key-file requires one file and may be specified only once\n"), -1);
            if (read_key_file(argv[i + 1], key) < 0)
                return (-1);
            *has_key = 1;
            key_source_seen = 1;
            i += 2;
            continue;
        }
        if (!end_options && (strcmp(argv[i], "-o") == 0
                || strcmp(argv[i], "--output") == 0))
        {
            if (i + 1 >= argc || argv[i + 1][0] == '\0' || output_seen)
                return (fprintf(stderr, "woody: --output requires one non-empty path and may be specified only once\n"), -1);
            *output_path = argv[i + 1];
            output_seen = 1;
            i += 2;
            continue;
        }
        if (!end_options && strcmp(argv[i], "--random-key") == 0)
        {
            if (key_source_seen)
                return (fprintf(stderr, "woody: --random-key conflicts with --key/--key-file\n"), -1);
            key_source_seen = 1;
            *has_key = 0;
            i++;
            continue;
        }
        if (!end_options && strcmp(argv[i], "--compress") == 0)
        {
            if (compress_seen)
                return (fprintf(stderr, "woody: --compress may be specified only once\n"), -1);
            *compress_payloads = 1;
            compress_seen = 1;
            i++;
            continue;
        }
        if (!end_options && argv[i][0] == '-')
            return (fprintf(stderr, "woody: unknown option: %s\n", argv[i]), -1);
        if (*input_path != NULL)
            return (fprintf(stderr, "woody: exactly one input ELF must be specified\n"), -1);
        *input_path = argv[i];
        i++;
    }
    if (*input_path == NULL)
        return (fprintf(stderr, "woody: missing input ELF\n"), -1);
    return (0);
}

int main(int argc, char **argv)
{
    unsigned char   *input;
    unsigned char   *output;
    unsigned char   key[WOODY_KEY_SIZE];
    unsigned char   random_material[WOODY_KEY_SIZE + WOODY_NONCE_SIZE];
    struct stat     input_identity;
    const char      *input_path;
    const char      *output_path;
    uint64_t        nonce;
    uint64_t        page_size;
    size_t          input_size;
    size_t          output_size;
    size_t          i;
    int             has_key;
    int             compress_payloads;
    int             parse_result;

    parse_result = parse_arguments(argc, argv, &input_path, &output_path,
            key, &has_key, &compress_payloads);
    if (parse_result != 0)
    {
        if (parse_result < 0)
            print_usage(stderr, argv[0]);
        return (parse_result > 0 ? 0 : 1);
    }
    if (woody_get_page_size(&page_size) < 0)
    {
        perror("cannot determine Linux page size");
        return (1);
    }
    if (page_size != WOODY_PAGE_SIZE)
    {
        fprintf(stderr, "woody: this build supports 4096-byte Linux pages only\n");
        return (1);
    }
    if (woody_load_file(input_path, &input, &input_size, &input_identity) < 0)
        return (1);
    if (has_key)
    {
        if (woody_random_bytes(random_material, WOODY_NONCE_SIZE) < 0)
        {
            perror("random nonce source");
            free(input);
            return (1);
        }
    }
    else if (woody_random_bytes(random_material, sizeof(random_material)) < 0)
    {
        perror("random key/nonce source");
        free(input);
        return (1);
    }
    if (!has_key)
    {
        i = 0;
        while (i < WOODY_KEY_SIZE)
        {
            key[i] = random_material[i];
            i++;
        }
    }
    nonce = 0;
    i = 0;
    while (i < WOODY_NONCE_SIZE)
    {
        nonce |= (uint64_t)random_material[i + (has_key ? 0U : WOODY_KEY_SIZE)]
            << (i * 8U);
        i++;
    }
    output = NULL;
    output_size = 0;
    if (input_size >= EI_NIDENT && input[EI_CLASS] == ELFCLASS32)
    {
        if (compress_payloads)
        {
            fprintf(stderr, "woody: --compress is currently supported for ELF64 only\n");
            free(input);
            return (1);
        }
        if (woody_pack_elf32(input, input_size, &output, &output_size,
                key, nonce) < 0)
        {
            free(input);
            return (1);
        }
    }
    else if (woody_pack_elf(input, input_size, &output, &output_size,
                key, nonce, compress_payloads) < 0)
    {
        free(input);
        return (1);
    }
    if (woody_write_file_atomic(output_path, output, output_size,
            &input_identity) < 0)
    {
        free(input);
        free(output);
        return (1);
    }
    woody_print_key(key, nonce);
    if (strcmp(output_path, WOODY_OUTPUT_NAME) != 0)
        printf("output_file: %s\n", output_path);
    free(input);
    free(output);
    return (0);
}
