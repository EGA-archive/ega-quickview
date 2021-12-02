/*
    Caching file system proxy
    Copyright (C) 2004  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/
#pragma once

#include <fuse.h>
#include <fuse_opt.h>

struct fuse_operations *cache_wrap(struct fuse_operations *oper);

void cache_print_options(void);
int cache_parse_options(struct fuse_args *args);

void cache_add_attr(const char *path, const struct stat *stbuf);

void cache_invalidate(const char *path);
