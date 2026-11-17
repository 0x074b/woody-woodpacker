#include "woody.h"

uint32_t woody_crc32(const unsigned char *buffer, size_t size)
{
    uint32_t crc;
    size_t i;
    unsigned int bit;

    crc = UINT32_C(0xFFFFFFFF);
    i = 0;
    while (i < size)
    {
        crc ^= buffer[i];
        bit = 0;
        while (bit < 8U)
        {
            if (crc & 1U)
                crc = (crc >> 1) ^ UINT32_C(0xEDB88320);
            else
                crc >>= 1;
            bit++;
        }
        i++;
    }
    return (~crc);
}
