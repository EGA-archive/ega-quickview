#pragma once

#include "includes.h"

struct fuse_operations* c4gh_wrap(struct fuse_operations *oper);

void c4ghfs_print_options(void);
int c4ghfs_parse_options(struct fuse_args *args);


size_t c4gh_size(size_t encrypted_filesize);
