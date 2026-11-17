#include "woody.h"

static int  read_urandom(unsigned char *buffer, size_t size)
{
    int         fd;
    size_t      done;
    ssize_t     amount;

    fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return (-1);
    done = 0;
    while (done < size)
    {
        amount = read(fd, buffer + done, size - done);
        if (amount < 0)
        {
            int saved_errno;

            if (errno == EINTR)
                continue;
            saved_errno = errno;
            (void)close(fd);
            errno = saved_errno;
            return (-1);
        }
        if (amount == 0)
        {
            (void)close(fd);
            errno = EIO;
            return (-1);
        }
        done += (size_t)amount;
    }
    if (close(fd) < 0)
        return (-1);
    return (0);
}

int woody_random_bytes(unsigned char *buffer, size_t size)
{
    size_t  done;
    long    amount;

    done = 0;
#ifdef SYS_getrandom
    while (done < size)
    {
        amount = syscall(SYS_getrandom, buffer + done, size - done, 0);
        if (amount < 0)
        {
            if (errno == EINTR)
                continue;
            break;
        }
        if (amount == 0)
            break;
        done += (size_t)amount;
    }
    if (done == size)
        return (0);
#endif
    if (read_urandom(buffer + done, size - done) < 0)
        return (-1);
    return (0);
}

int woody_get_page_size(uint64_t *page_size)
{
    int             fd;
    Elf64_auxv_t    entry;
    unsigned char   *bytes;
    size_t          done;
    ssize_t         amount;
    int             found;

    *page_size = 0;
    fd = open("/proc/self/auxv", O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return (-1);
    found = 0;
    while (!found)
    {
        bytes = (unsigned char *)&entry;
        done = 0;
        while (done < sizeof(entry))
        {
            amount = read(fd, bytes + done, sizeof(entry) - done);
            if (amount < 0)
            {
                int saved_errno;

                if (errno == EINTR)
                    continue;
                saved_errno = errno;
                (void)close(fd);
                errno = saved_errno;
                return (-1);
            }
            if (amount == 0)
            {
                close(fd);
                errno = EIO;
                return (-1);
            }
            done += (size_t)amount;
        }
        if (entry.a_type == AT_PAGESZ)
        {
            *page_size = entry.a_un.a_val;
            found = 1;
        }
        else if (entry.a_type == AT_NULL)
            break;
    }
    if (close(fd) < 0)
        return (-1);
    if (!found || *page_size == 0)
    {
        errno = EINVAL;
        return (-1);
    }
    return (0);
}

void woody_print_key(const unsigned char key[WOODY_KEY_SIZE], uint64_t nonce)
{
    size_t i;

    printf("key_value: ");
    i = 0;
    while (i < WOODY_KEY_SIZE)
    {
        printf("%02X", (unsigned int)key[i]);
        i++;
    }
    printf("\nnonce_value: %016" PRIX64 "\n", nonce);
}
