// Prints the file named by its argument through a private read-only mapping, so a read the
// fanotify daemon denies arrives as SIGBUS rather than as a read(2) error.
//
//   cc -static -O2 -o mmap-cat misc/fanotify/mmap-cat.c
#include <fcntl.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/stat.h>

int main(int argc, char **argv) {
    struct stat st;
    int fd = argc == 2 ? open(argv[1], O_RDONLY) : -1;
    if (fd < 0 || fstat(fd, &st) != 0) {
        perror(argc == 2 ? argv[1] : "usage: mmap-cat <file>");
        return 1;
    }
    if (st.st_size == 0)
        return 0;
    char *p = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (p == MAP_FAILED) {
        perror("mmap");
        return 1;
    }
    return fwrite(p, 1, st.st_size, stdout) == (size_t)st.st_size ? 0 : 1;
}
