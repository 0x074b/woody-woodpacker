#include "woody.h"

#define LZSS_HASH_SIZE 4096U
#define LZSS_MAX_MATCH 18U
#define LZSS_MIN_MATCH 3U
#define LZSS_MAX_DISTANCE 4095U

static uint32_t hash3(const unsigned char *p)
{
    return (((uint32_t)p[0] * 251U + (uint32_t)p[1] * 31U + p[2])
        & (LZSS_HASH_SIZE - 1U));
}

int woody_lzss_compress(const unsigned char *input, size_t input_size,
        unsigned char **output, size_t *output_size)
{
    int64_t *last;
    unsigned char *encoded;
    size_t capacity;
    size_t pos;
    size_t out;
    size_t control_pos;
    size_t token;
    size_t length;
    size_t distance;
    size_t previous;
    size_t update;
    uint32_t hash;

    *output = NULL;
    *output_size = 0;
    if (input_size > SIZE_MAX - input_size / 8U - 16U)
    {
        errno = EOVERFLOW;
        return (-1);
    }
    capacity = input_size + input_size / 8U + 16U;
    encoded = (unsigned char *)malloc(capacity == 0 ? 1U : capacity);
    last = (int64_t *)malloc(LZSS_HASH_SIZE * sizeof(*last));
    if (encoded == NULL || last == NULL)
    {
        free(encoded);
        free(last);
        return (perror("malloc LZSS"), -1);
    }
    for (hash = 0; hash < LZSS_HASH_SIZE; hash++)
        last[hash] = -1;
    pos = 0;
    out = 0;
    while (pos < input_size)
    {
        control_pos = out++;
        encoded[control_pos] = 0;
        token = 0;
        while (token < 8U && pos < input_size)
        {
            length = 0;
            previous = 0;
            hash = 0;
            if (input_size - pos >= LZSS_MIN_MATCH)
            {
                hash = hash3(input + pos);
                if (last[hash] >= 0)
                    previous = (size_t)last[hash];
                if (last[hash] >= 0 && pos > previous
                    && pos - previous <= LZSS_MAX_DISTANCE)
                {
                    length = 0;
                    while (length < LZSS_MAX_MATCH
                        && length < input_size - pos
                        && input[previous + length] == input[pos + length])
                        length++;
                }
                last[hash] = (int64_t)pos;
            }
            if (length >= LZSS_MIN_MATCH)
            {
                distance = pos - previous;
                encoded[out++] = (unsigned char)distance;
                encoded[out++] = (unsigned char)(((distance >> 8) << 4)
                    | (length - LZSS_MIN_MATCH));
                update = 1U;
                while (update < length && input_size - (pos + update) >= LZSS_MIN_MATCH)
                {
                    last[hash3(input + pos + update)] = (int64_t)(pos + update);
                    update++;
                }
                pos += length;
            }
            else
            {
                encoded[control_pos] |= (unsigned char)(1U << token);
                encoded[out++] = input[pos];
                pos++;
            }
            token++;
        }
    }
    free(last);
    *output = encoded;
    *output_size = out;
    return (0);
}
