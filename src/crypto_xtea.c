#include "woody.h"

static void store_u64_le(unsigned char *p, uint32_t low, uint32_t high)
{
    p[0] = (unsigned char)low;
    p[1] = (unsigned char)(low >> 8);
    p[2] = (unsigned char)(low >> 16);
    p[3] = (unsigned char)(low >> 24);
    p[4] = (unsigned char)high;
    p[5] = (unsigned char)(high >> 8);
    p[6] = (unsigned char)(high >> 16);
    p[7] = (unsigned char)(high >> 24);
}

static void xtea_encrypt_block(uint32_t *v0, uint32_t *v1,
        const uint32_t key[4])
{
    uint32_t sum;
    uint32_t mix;
    unsigned int round;

    sum = 0;
    round = 0;
    while (round < 32)
    {
        mix = (((*v1 << 4) ^ (*v1 >> 5)) + *v1)
            ^ (sum + key[sum & 3U]);
        *v0 += mix;
        sum += 0x9E3779B9U;
        mix = (((*v0 << 4) ^ (*v0 >> 5)) + *v0)
            ^ (sum + key[(sum >> 11) & 3U]);
        *v1 += mix;
        round++;
    }
}

void woody_xtea_ctr(unsigned char *buffer, size_t size,
        const uint32_t key[4], uint64_t nonce)
{
    uint64_t counter;
    uint32_t v0;
    uint32_t v1;
    unsigned char stream[8];
    size_t offset;
    size_t amount;
    size_t i;

    offset = 0;
    while (offset < size)
    {
        counter = nonce + (uint64_t)(offset / 8U);
        v0 = (uint32_t)counter;
        v1 = (uint32_t)(counter >> 32);
        xtea_encrypt_block(&v0, &v1, key);
        store_u64_le(stream, v0, v1);
        amount = size - offset;
        if (amount > 8U)
            amount = 8U;
        i = 0;
        while (i < amount)
        {
            buffer[offset + i] ^= stream[i];
            i++;
        }
        offset += amount;
    }
}

