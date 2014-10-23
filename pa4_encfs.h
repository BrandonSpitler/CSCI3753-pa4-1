/*

  Christopher Costello

  Modified from fusexmp.c by Miklos Szeredi and Andy Sayler,
  and params.h by Joseph Pfeiffer:

*/

#ifndef _PARAMS_H_
#define _PARAMS_H_

#define FUSE_USE_VERSION 28

#define _XOPEN_SOURCE 700

#include <limits.h>
#include <stdio.h>
struct pa4_state {
    char *rootdir;
    char *passPhrase;
};

#define PA4_DATA ((struct pa4_state *) fuse_get_context()->private_data)


#endif


#define HAVE_SETXATTR

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define AES_ENCRYPT 1
#define AES_DECRYPT 0
#define AES_PASSTHRU -1

#define XATTR_ENCRYPTED "user.encrypted"
#define ENCRYPTED "true"
#define UNENCRYPTED "false"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <fuse.h>
#include <libgen.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <unistd.h>

#include "aes-crypt.h"
