#pragma once

#include "includes.h"

int ssh_connect(void);

extern struct fuse_operations sshfs_oper;

void sshfs_print_options(void);
int sshfs_parse_options(struct fuse_args *args);
void sshfs_clean(void);


struct conn {
	pthread_mutex_t lock_write;
	int processing_thread_started;
	int rfd;
	int wfd;
	int connver;
	int req_count;
	int dir_count;
	int file_count;
};

struct buffer {
	uint8_t *p;
	size_t len;
	size_t size;
};


struct list_head {
	struct list_head *prev;
	struct list_head *next;
};


struct sshfs_io {
	int num_reqs;
	pthread_cond_t finished;
	int error;
};

struct read_chunk {
	off_t offset;
	size_t size;
	int refs;
	struct list_head reqs;
	struct sshfs_io sio;
};

struct sshfs_file {
	struct buffer handle;
	struct list_head write_reqs;
	pthread_cond_t write_finished;
	int write_error;
	struct read_chunk *readahead;
	off_t next_pos;
	int is_seq;
	struct conn *conn;
	int connver;

        /* For the encrypted files */
        off_t remote_size;
};
