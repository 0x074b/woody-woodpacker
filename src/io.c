#include "woody.h"

static int read_all(int fd, unsigned char *buffer, size_t size)
{
    size_t done;
    ssize_t amount;

    done = 0;
    while (done < size)
    {
        amount = read(fd, buffer + done, size - done);
        if (amount < 0)
        {
            if (errno == EINTR)
                continue;
            return (-1);
        }
        if (amount == 0)
        {
            errno = EIO;
            return (-1);
        }
        done += (size_t)amount;
    }
    return (0);
}

static int write_all(int fd, const unsigned char *buffer, size_t size)
{
    size_t done;
    ssize_t amount;

    done = 0;
    while (done < size)
    {
        amount = write(fd, buffer + done, size - done);
        if (amount < 0)
        {
            if (errno == EINTR)
                continue;
            return (-1);
        }
        if (amount == 0)
        {
            errno = EIO;
            return (-1);
        }
        done += (size_t)amount;
    }
    return (0);
}

int woody_load_file(const char *path, unsigned char **buffer, size_t *size,
        struct stat *identity)
{
    int             fd;
    struct stat     st;
    struct stat     after_read;
    unsigned char   *data;

    *buffer = NULL;
    *size = 0;
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return (perror(path), -1);
    while (syscall(SYS_fstat, fd, &st) < 0)
    {
        if (errno == EINTR)
            continue;
        perror("fstat");
        close(fd);
        return (-1);
    }
    if (!S_ISREG(st.st_mode) || st.st_size <= 0
        || (uintmax_t)st.st_size > (uintmax_t)SIZE_MAX)
    {
        fprintf(stderr, "woody: input must be a non-empty regular file\n");
        close(fd);
        return (-1);
    }
    data = (unsigned char *)malloc((size_t)st.st_size);
    if (data == NULL)
    {
        perror("malloc");
        close(fd);
        return (-1);
    }
    if (read_all(fd, data, (size_t)st.st_size) < 0)
    {
        perror("read");
        free(data);
        close(fd);
        return (-1);
    }
    while (syscall(SYS_fstat, fd, &after_read) < 0)
    {
        if (errno == EINTR)
            continue;
        perror("fstat after read");
        free(data);
        close(fd);
        return (-1);
    }
    if (after_read.st_dev != st.st_dev || after_read.st_ino != st.st_ino
        || after_read.st_size != st.st_size
        || after_read.st_mtim.tv_sec != st.st_mtim.tv_sec
        || after_read.st_mtim.tv_nsec != st.st_mtim.tv_nsec
        || after_read.st_ctim.tv_sec != st.st_ctim.tv_sec
        || after_read.st_ctim.tv_nsec != st.st_ctim.tv_nsec)
    {
        fprintf(stderr, "woody: input changed while it was being read\n");
        free(data);
        close(fd);
        return (-1);
    }
    if (close(fd) < 0)
    {
        perror("close");
        free(data);
        return (-1);
    }
    *identity = st;
    *buffer = data;
    *size = (size_t)st.st_size;
    return (0);
}

static int same_file(const char *path, const struct stat *identity)
{
    struct stat target;

    while (syscall(SYS_newfstatat, AT_FDCWD, path, &target, 0) < 0)
    {
        if (errno == EINTR)
            continue;
        if (errno == ENOENT)
            return (0);
        perror("stat output");
        return (-1);
    }
    if (target.st_dev == identity->st_dev && target.st_ino == identity->st_ino)
    {
        fprintf(stderr, "woody: refusing to replace the input file\n");
        errno = EINVAL;
        return (1);
    }
    return (0);
}

int woody_write_file_atomic(const char *path, const unsigned char *buffer,
        size_t size, const struct stat *input_identity)
{
    char        *temporary;
    size_t      path_length;
    size_t      temporary_capacity;
    long        pid;
    unsigned int attempt;
    int         fd;
    int         saved_errno;

    if (same_file(path, input_identity) != 0)
        return (-1);
    path_length = 0;
    while (path[path_length] != '\0')
    {
        if (path_length == SIZE_MAX - 64U)
        {
            errno = ENAMETOOLONG;
            return (perror("output path"), -1);
        }
        path_length++;
    }
    temporary_capacity = path_length + 64U;
    temporary = (char *)malloc(temporary_capacity);
    if (temporary == NULL)
        return (perror("malloc"), -1);
    pid = syscall(SYS_getpid);
    attempt = 0;
    fd = -1;
    while (attempt < 32U)
    {
        (void)snprintf(temporary, temporary_capacity, "%s.tmp.%ld.%u",
            path, pid, attempt);
        fd = open(temporary, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        if (fd >= 0)
            break;
        if (errno != EEXIST)
        {
            perror(temporary);
            free(temporary);
            return (-1);
        }
        attempt++;
    }
    if (fd < 0)
    {
        fprintf(stderr, "woody: cannot allocate a temporary output file\n");
        free(temporary);
        return (-1);
    }
    if (syscall(SYS_fchmod, fd, 0755) < 0)
    {
        saved_errno = errno;
        perror("chmod temporary output");
        (void)close(fd);
        (void)syscall(SYS_unlink, temporary);
        free(temporary);
        errno = saved_errno;
        return (-1);
    }
    if (write_all(fd, buffer, size) < 0)
    {
        saved_errno = errno;
        perror("write temporary output");
        (void)close(fd);
        (void)syscall(SYS_unlink, temporary);
        free(temporary);
        errno = saved_errno;
        return (-1);
    }
    while (syscall(SYS_fsync, fd) < 0)
    {
        if (errno == EINTR)
            continue;
        saved_errno = errno;
        perror("fsync output");
        (void)close(fd);
        (void)syscall(SYS_unlink, temporary);
        free(temporary);
        errno = saved_errno;
        return (-1);
    }
    if (close(fd) < 0)
    {
        saved_errno = errno;
        perror("close output");
        (void)syscall(SYS_unlink, temporary);
        free(temporary);
        errno = saved_errno;
        return (-1);
    }
    if (syscall(SYS_rename, temporary, path) < 0)
    {
        saved_errno = errno;
        perror("rename output");
        (void)syscall(SYS_unlink, temporary);
        free(temporary);
        errno = saved_errno;
        return (-1);
    }
    free(temporary);
    return (0);
}
