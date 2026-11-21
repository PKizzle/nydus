// Takes a file handle for each path, evicts the dentry cache, then reopens every handle with
// open_by_handle_at(2) and checks it still names the same object with the same content.
//
// Usage: fh-reopen <mountpoint> <path>...   (paths relative to the mountpoint; needs root)
// Prints one line per path and exits non-zero if any handle fails.
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

// FNV-1a over a regular file's bytes, or over a directory's entry names.
static uint64_t digest_fd(int fd, int is_dir) {
	uint64_t h = 1469598103934665603ULL;
	if (is_dir) {
		DIR *d = fdopendir(fd);
		struct dirent *e;
		if (!d)
			return 0;
		while ((e = readdir(d)) != NULL)
			for (const char *p = e->d_name; *p; p++)
				h = (h ^ (unsigned char)*p) * 1099511628211ULL;
		closedir(d);
		return h;
	}
	unsigned char buf[65536];
	ssize_t n;
	while ((n = read(fd, buf, sizeof(buf))) > 0)
		for (ssize_t i = 0; i < n; i++)
			h = (h ^ buf[i]) * 1099511628211ULL;
	close(fd);
	return n < 0 ? 0 : h;
}

int main(int argc, char **argv) {
	if (argc < 3) {
		fprintf(stderr, "usage: %s <mountpoint> <path>...\n", argv[0]);
		return 2;
	}
	int mount_fd = open(argv[1], O_RDONLY | O_DIRECTORY);
	if (mount_fd < 0) {
		perror(argv[1]);
		return 2;
	}
	int n = argc - 2, failures = 0;
	struct file_handle **fh = calloc(n, sizeof(*fh));
	struct stat *st = calloc(n, sizeof(*st));
	uint64_t *want = calloc(n, sizeof(*want));

	for (int i = 0; i < n; i++) {
		const char *path = argv[i + 2];
		int mnt_id, fd = openat(mount_fd, path, O_RDONLY);
		if (fd < 0 || fstat(fd, &st[i]) < 0) {
			fprintf(stderr, "%s: open: %s\n", path, strerror(errno));
			return 2;
		}
		want[i] = digest_fd(fd, S_ISDIR(st[i].st_mode));
		fh[i] = malloc(sizeof(struct file_handle) + MAX_HANDLE_SZ);
		fh[i]->handle_bytes = MAX_HANDLE_SZ;
		if (name_to_handle_at(mount_fd, path, fh[i], &mnt_id, 0) < 0) {
			fprintf(stderr, "%s: name_to_handle_at: %s\n", path, strerror(errno));
			return 2;
		}
	}

	// Evict every unused dentry and inode, so each reopen must look the node id up again.
	sync();
	int dc = open("/proc/sys/vm/drop_caches", O_WRONLY);
	if (dc < 0 || write(dc, "2", 1) != 1) {
		perror("drop_caches");
		return 2;
	}
	close(dc);

	for (int i = 0; i < n; i++) {
		const char *path = argv[i + 2];
		const char *kind = S_ISDIR(st[i].st_mode) ? "directory" : "file";
		int fd = open_by_handle_at(mount_fd, fh[i], O_RDONLY);
		struct stat now;
		if (fd < 0) {
			printf("FAIL %s %s: open_by_handle_at: %s\n", kind, path, strerror(errno));
			failures++;
			continue;
		}
		if (fstat(fd, &now) < 0 || now.st_ino != st[i].st_ino) {
			printf("FAIL %s %s: reopened inode %lu, expected %lu\n", kind, path,
			       (unsigned long)now.st_ino, (unsigned long)st[i].st_ino);
			close(fd);
			failures++;
			continue;
		}
		if (digest_fd(fd, S_ISDIR(st[i].st_mode)) != want[i]) {
			printf("FAIL %s %s: content differs after reopen\n", kind, path);
			failures++;
			continue;
		}
		printf("ok   %s %s: reopened, same inode and content\n", kind, path);
	}
	return failures ? 1 : 0;
}
