/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

  Minor modifications and note by Andy Sayler (2012) <www.andysayler.com>

  Additional modifications by Christopher Costello (2014) 
  
  Source: fuse-2.8.7.tar.gz examples directory
  http://sourceforge.net/projects/fuse/files/fuse-2.X/

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.

  gcc -Wall `pkg-config fuse --cflags` pa4_encfs.c -o pa4_encfs `pkg-config fuse --libs`

  Note: This implementation is largely stateless and does not maintain
  open file handels between open and release calls (fi->fh).
  Instead, files are opened and closed as necessary inside read(), write(),
  etc calls. As such, the functions that rely on maintaining file handles are
  not implmented (fgetattr(), etc). Those seeking a more efficient and
  more complete implementation may wish to add fi->fh support to minimize
  open() and close() calls and support fh dependent functions.

*/

#include "pa4_encfs.h"

static int pa4_error(char *str) {
  int ret = -errno;
  (void) str;

  return ret;
}

//  All the paths I see are relative to the root of the mounted
//  filesystem.  In order to get to the underlying filesystem, I need to
//  have the mountpoint.  I'll save it away early on in main(), and then
//  whenever I need a path for something I'll call this to construct
//  it.
static void pa4_fullpath(char fpath[PATH_MAX], const char *path) {
  strcpy(fpath, PA4_DATA->rootdir);
  strncat(fpath, path, PATH_MAX); // ridiculously long paths will break here
}

static int pa4_getattr(const char *path, struct stat *statbuf) {
  int retstat = 0;
  char fpath[PATH_MAX];

  pa4_fullpath(fpath, path);

  retstat = lstat(fpath, statbuf);
  if (retstat != 0)
    retstat = pa4_error("pa4_getattr lstat");

  return retstat;
}

static int pa4_access(const char *path, int mask) {
  int res;
  char fpath[PATH_MAX];

  pa4_fullpath(fpath, path);

  res = access(fpath, mask);
  if (res == -1)
    return -errno;

  return 0;
}

static int pa4_readlink(const char *path, char *buf, size_t size) {
  int res;
  char fpath[PATH_MAX];

  pa4_fullpath(fpath, path);

  res = readlink(fpath, buf, size - 1);
  if (res == -1)
    return -errno;

  buf[res] = '\0';
  return 0;
}

static int pa4_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi) {
    DIR *dp;
  struct dirent *de;

  (void) offset;
  (void) fi;

  char fpath[PATH_MAX];
  pa4_fullpath(fpath, path);

  dp = opendir(fpath);
  if (dp == NULL)
    return -errno;

  while ((de = readdir(dp)) != NULL) {
    struct stat st;
    memset(&st, 0, sizeof(st));
    st.st_ino = de->d_ino;
    st.st_mode = de->d_type << 12;
    if (filler(buf, de->d_name, &st, 0))
      break;
  }

  closedir(dp);
  return 0;
}

static int pa4_mknod(const char *path, mode_t mode, dev_t rdev) {
  int res;
  char fpath[PATH_MAX];

  pa4_fullpath(fpath, path);

  /* On Linux this could just be 'mknod(path, mode, rdev)' but this
     is more portable */
  if (S_ISREG(mode)) {
    res = open(fpath, O_CREAT | O_EXCL | O_WRONLY, mode);
    if (res >= 0)
      res = close(res);
  } else if (S_ISFIFO(mode))
    res = mkfifo(fpath, mode);
  else
    res = mknod(fpath, mode, rdev);
  if (res == -1)
    return -errno;

  return 0;
}

static int pa4_mkdir(const char *path, mode_t mode) {
  int res;
  char fpath[PATH_MAX];

  pa4_fullpath(fpath, path);

  res = mkdir(fpath, mode);
  if (res == -1)
    return -errno;

  return 0;
}

static int pa4_unlink(const char *path) {
  int res;
  char fpath[PATH_MAX];

  pa4_fullpath(fpath, path);

  res = unlink(fpath);
  if (res == -1)
    return -errno;

  return 0;
}

static int pa4_rmdir(const char *path) {
  int res;
  char fpath[PATH_MAX];

  pa4_fullpath(fpath, path);

  res = rmdir(fpath);
  if (res == -1)
    return -errno;

  return 0;
}

static int pa4_symlink(const char *from, const char *to) {
  int res;

  res = symlink(from, to);
  if (res == -1)
    return -errno;

  return 0;
}

static int pa4_rename(const char *from, const char *to) {
  int res;

  res = rename(from, to);
  if (res == -1)
    return -errno;

  return 0;
}

static int pa4_link(const char *from, const char *to) {
  int res;

  res = link(from, to);
  if (res == -1)
    return -errno;

  return 0;
}

static int pa4_chmod(const char *path, mode_t mode) {
  int res;
  char fpath[PATH_MAX];

  pa4_fullpath(fpath, path);

  res = chmod(fpath, mode);
  if (res == -1)
    return -errno;

  return 0;
}

static int pa4_chown(const char *path, uid_t uid, gid_t gid) {
  int res;
  char fpath[PATH_MAX];

  pa4_fullpath(fpath, path);

  res = lchown(fpath, uid, gid);
  if (res == -1)
    return -errno;

  return 0;
}

static int pa4_truncate(const char *path, off_t size) {
  int res;
  char fpath[PATH_MAX];

  pa4_fullpath(fpath, path);

  res = truncate(fpath, size);
  if (res == -1)
    return -errno;

  return 0;
}

static int pa4_utimens(const char *path, const struct timespec ts[2]) {
  int res;
  struct timeval tv[2];
  char fpath[PATH_MAX];

  pa4_fullpath(fpath, path);

  tv[0].tv_sec = ts[0].tv_sec;
  tv[0].tv_usec = ts[0].tv_nsec / 1000;
  tv[1].tv_sec = ts[1].tv_sec;
  tv[1].tv_usec = ts[1].tv_nsec / 1000;

  res = utimes(fpath, tv);
  if (res == -1)
    return -errno;

  return 0;
}

static int pa4_open(const char *path, struct fuse_file_info *fi) {
  int res;
  char fpath[PATH_MAX];

  pa4_fullpath(fpath, path);

  res = open(fpath, fi->flags);
  if (res == -1)
    return -errno;

  close(res);
  return 0;
}

static int pa4_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
  int res;
  FILE *f, *memfile;
  char fpath[PATH_MAX];
  char *memtext;
  size_t memsize;
  int crypt_action = AES_PASSTHRU;
  char xattr_value[8];
  ssize_t xattr_len;

  pa4_fullpath(fpath, path);

  // void out unused params
  (void) fi;

  // open the file for reading
  f = fopen(fpath, "r");
  if (f == NULL)
    return -errno;

  // open an in-memory "file"
  memfile = open_memstream(&memtext, &memsize);
  if (memfile == NULL)
    return -errno;

  // check the file's xattr to see if we're decrypting it
  xattr_len = getxattr(fpath, XATTR_ENCRYPTED, xattr_value, 8);
  if (xattr_len != -1 && !memcmp(xattr_value, ENCRYPTED, 4)){
    crypt_action = AES_DECRYPT;
  }

  // decrypt the real file's bytes into the in-memory "file"
  do_crypt(f, memfile, crypt_action, PA4_DATA->passPhrase);
  fclose(f);

  // read the decrypted bytes into the buffer param
  fflush(memfile);
  fseek(memfile, offset, SEEK_SET);
  res = fread(buf, 1, size, memfile);
  if (res == -1)
    res = -errno;

  fclose(memfile);

  return res;
}

// get the file's bytes and decrypt them in memory, then add the bytes to be written,
// then encrypt them all and write them
static int pa4_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
  int res;
  char fpath[PATH_MAX];
  FILE *f, *memfile;
  char *memtext;
  size_t memsize;
  int crypt_action = AES_PASSTHRU;
  char xattr_value[8];
  ssize_t xattr_len;

  pa4_fullpath(fpath, path);

  // void out unused params
  (void) fi;

  // open the file for reading so we can get its bytes, unencrypted, in memory
  f = fopen(fpath, "r");
  if (f == NULL)
    return -errno;

  // open an in-memory "file"
  memfile = open_memstream(&memtext, &memsize);
  if (memfile == NULL)
    return -errno;

  // check the file's xattr to see if we're decrypting it
  xattr_len = getxattr(fpath, XATTR_ENCRYPTED, xattr_value, 8);
  if (xattr_len != -1 && !memcmp(xattr_value, ENCRYPTED, 4)){
    crypt_action = AES_DECRYPT;
  }

  // get the file decrypted and in memory
  do_crypt(f, memfile, crypt_action, PA4_DATA->passPhrase);
  fclose(f);

  // add the bytes in buf to the in-memory "file"
  fseek(memfile, offset, SEEK_SET);
  res = fwrite(buf, 1, size, memfile);
  if (res == -1)
    res = -errno;
  fflush(memfile);

  // if we decrypted when we opened the file, switch to encrypting now
  if (crypt_action == AES_DECRYPT) {
    crypt_action = AES_ENCRYPT;
  }

  // re-open the real file for writing, encrypt & add the new contents
  f = fopen(fpath, "w");
  fseek(memfile, 0, SEEK_SET);
  do_crypt(memfile, f, crypt_action, PA4_DATA->passPhrase);

  fclose(memfile);
  fclose(f);

  return res;
}

static int pa4_statfs(const char *path, struct statvfs *stbuf) {
  int res;
  char fpath[PATH_MAX];

  pa4_fullpath(fpath, path);

  res = statvfs(fpath, stbuf);
  if (res == -1)
    return -errno;

  return 0;
}

static int pa4_create(const char* path, mode_t mode, struct fuse_file_info* fi) {
  char fpath[PATH_MAX];
  FILE *f, *memfile;
  char *memtext;
  size_t memsize;

  pa4_fullpath(fpath, path);

  (void) fi;
  (void) mode;

  // create the file
  f = fopen(fpath, "w");
  if (f == NULL)
    return -errno;

  // open an in-memory "file"
  memfile = open_memstream(&memtext, &memsize);
  if (memfile == NULL)
    return -errno;

  // encrypt the in-memory "file" into the opened file
  do_crypt(memfile, f, AES_ENCRYPT, PA4_DATA->passPhrase);
  fclose(memfile);

  // set the xattr so we know how to open the file later
  if (setxattr(fpath, XATTR_ENCRYPTED, ENCRYPTED, 4, 0)){
    return -errno;
  }

  fclose(f);

  return 0;
}

static int pa4_release(const char *path, struct fuse_file_info *fi) {
  /* Just a stub. This method is optional and can safely be left
     unimplemented */

  (void) path;
  (void) fi;
  return 0;
}

static int pa4_fsync(const char *path, int isdatasync, struct fuse_file_info *fi) {
  /* Just a stub. This method is optional and can safely be left
     unimplemented */

  (void) path;
  (void) isdatasync;
  (void) fi;
  return 0;
}

static int pa4_setxattr(const char *path, const char *name, const char *value, size_t size, int flags) {
  int res;
  char fpath[PATH_MAX];

  pa4_fullpath(fpath, path);

  res = lsetxattr(fpath, name, value, size, flags);
  if (res == -1)
    return -errno;
  return 0;
}

static int pa4_getxattr(const char *path, const char *name, char *value, size_t size) {
  int res;
  char fpath[PATH_MAX];

  pa4_fullpath(fpath, path);

  res = lgetxattr(fpath, name, value, size);
  if (res == -1)
    return -errno;
  return res;
}

static int pa4_listxattr(const char *path, char *list, size_t size) {
  int res;
  char fpath[PATH_MAX];

  pa4_fullpath(fpath, path);

  res = llistxattr(fpath, list, size);
  if (res == -1)
    return -errno;
  return res;
}

static int pa4_removexattr(const char *path, const char *name) {
  int res;
  char fpath[PATH_MAX];

  pa4_fullpath(fpath, path);

  res = lremovexattr(fpath, name);
  if (res == -1)
    return -errno;
  return 0;
}

void *pa4_init(struct fuse_conn_info *conn) {
  (void) conn;
  return PA4_DATA;
}

/** Open directory
 *
 * This method should check if the open operation is permitted for
 * this  directory
 *
 * Introduced in version 2.3
 */
int pa4_opendir(const char *path, struct fuse_file_info *fi) {
    DIR *dp;
    int retstat = 0;
    char fpath[PATH_MAX];

    pa4_fullpath(fpath, path);

    dp = opendir(fpath);
    if (dp == NULL)
      retstat = pa4_error("pa4_opendir opendir");

    fi->fh = (intptr_t) dp;

    return retstat;
}

/**
 * Release directory
 */
int pa4_releasedir(const char *path, struct fuse_file_info *fi) {
    int retstat = 0;
    (void) path;

    closedir((DIR *) (uintptr_t) fi->fh);

    return retstat;
}

void pa4_usage() {
    fprintf(stderr, "usage: pa4_encfs [FUSE and mount options] passPhrase rootDir mountPoint\n");
    abort();
}

static struct fuse_operations pa4_oper = {
  .getattr	= pa4_getattr,
  .access	= pa4_access,
  .readlink	= pa4_readlink,
  .readdir	= pa4_readdir,
  .mknod	= pa4_mknod,
  .mkdir	= pa4_mkdir,
  .symlink	= pa4_symlink,
  .unlink	= pa4_unlink,
  .rmdir	= pa4_rmdir,
  .rename	= pa4_rename,
  .link		= pa4_link,
  .chmod	= pa4_chmod,
  .chown	= pa4_chown,
  .truncate	= pa4_truncate,
  .utimens	= pa4_utimens,
  .open		= pa4_open,
  .read		= pa4_read,
  .write	= pa4_write,
  .statfs	= pa4_statfs,
  .create	= pa4_create,
  .release	= pa4_release,
  .fsync	= pa4_fsync,
  .setxattr	= pa4_setxattr,
  .getxattr	= pa4_getxattr,
  .listxattr	= pa4_listxattr,
  .removexattr	= pa4_removexattr,
  .init		= pa4_init,
  .releasedir	= pa4_releasedir,
  .opendir	= pa4_opendir
};

int main(int argc, char *argv[]) {
  umask(0);

  int fuse_stat;
  struct pa4_state *pa4_data;

  if ((argc < 3) || (argv[argc-2][0] == '-') || (argv[argc-1][0] == '-'))
    pa4_usage();

  pa4_data = malloc(sizeof(struct pa4_state));
  if (pa4_data == NULL) {
    perror("main calloc");
    abort();
  }

  // pull the pass phrase and rootdir out of the argument list
  pa4_data->passPhrase = argv[argc-3];
  pa4_data->rootdir = realpath(argv[argc-2], NULL);

  argv[argc-3] = argv[argc-1];
  argv[argc-2] = NULL;
  argv[argc-1] = NULL;
  argc -= 2;

  // turn over control to fuse
  fprintf(stderr, "about to call fuse_main\n");
  fuse_stat = fuse_main(argc, argv, &pa4_oper, pa4_data);
  fprintf(stderr, "fuse_main returned %d\n", fuse_stat);

  return fuse_stat;
}
