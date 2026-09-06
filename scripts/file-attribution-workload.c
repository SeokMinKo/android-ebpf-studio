// Isolated device acceptance workload. Only accesses its two explicit file paths.
// Build with Android NDK clang; run: workload /tmp/unique/read-A.bin /tmp/unique/read-B.bin
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static void fail(const char *operation) { perror(operation); exit(1); }

int main(int argc, char **argv) {
    if (argc != 3) return 2;
    void *buffer = NULL;
    if (posix_memalign(&buffer, 4096, 65536)) return 3;
    // O_EXCL prevents accidental overwrite of any existing user file.
    for (int file = 1; file <= 2; file++) {
        int fd = open(argv[file], O_CREAT | O_EXCL | O_RDWR, 0600);
        if (fd < 0) fail("create");
        memset(buffer, file == 1 ? 0xA5 : 0x5A, 65536);
        for (int i = 0; i < 64; i++) if (write(fd, buffer, 65536) != 65536) fail("write");
        if (fsync(fd)) fail("fsync");
        struct stat st;
        if (fstat(fd, &st)) fail("fstat");
        printf("FILE path=%s dev=%llu inode=%llu bytes=%lld\n", argv[file],
            (unsigned long long)st.st_dev, (unsigned long long)st.st_ino, (long long)st.st_size);
        close(fd);
    }
    fflush(stdout);
    for (int file = 1; file <= 2; file++) {
        int fd = open(argv[file], O_RDONLY | O_DIRECT);
        if (fd < 0) fail("open direct");
        usleep(300000);
        for (int i = 0; i < 64; i++) {
            ssize_t count = read(fd, buffer, 65536);
            if (count != 65536) fail("read direct");
            for (int j = 0; j < count; j++) if (((unsigned char *)buffer)[j] != (file == 1 ? 0xA5 : 0x5A)) {
                fprintf(stderr, "data mismatch\n"); return 4;
            }
            usleep(10000);
        }
        usleep(300000); // Keep the FD alive for asynchronous path resolution.
        close(fd);
        printf("READ_OK path=%s bytes=4194304 direct=1\n", argv[file]);
        fflush(stdout);
    }
    free(buffer);
    return 0;
}
