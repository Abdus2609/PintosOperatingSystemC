#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "filesys/filesys.h"
#include <stdbool.h>
#include <list.h>
#include "../threads/thread.h"

#define ERROR_RETURN -1
#define STDIN_FD 0
#define STDOUT_FD 1
#define TOTAL_NUM_SYSCALLS 20
#define FIRST_AVAILABLE_FD 2
#define FIRST_AVAILABLE_MAPID 1
#define BOTTOM_OF_STACK (void *) (0xc0000000 - 0x7a1200)

typedef int pid_t;
typedef int mapid_t;

extern struct lock filesys_lock;

struct file_elem {
    struct file *file;      /* The actual file */
    int fd;                 /* The file descriptor */
    struct list_elem elem;  /* Elem to store files in a threads file list */
    bool mapped;            /* Boolean stating whether file is mapped */
    mapid_t mapid;          /* MapID of file - 0 if unmapped */
    void *mapped_addr;      /* The location of the mapped file in memory */
    int mem_file_size;      /* Size of file in memory */
};

/* The context of memory access so when checking the address, false is
    returned only when it is meant to be */
enum access_type {
    READ,       /* For the read syscall */
    WRITE_M,    /* Writing from a mapped file */
    OTHER
};

/* Distinguishes between searching the file list for a specific 
    file descriptor or mapid */
enum search_type {
    FILE_DESC,
    MAP_ID
};

void syscall_init (void);

void halt(void);
void exit(int status);
pid_t exec(const char *cmd_line);
int wait(pid_t pid);
bool create(const char* file, unsigned initial_size);
bool remove(const char* file);
int open(const char* file);
int filesize(int fd);
int read(int fd, void *buffer, unsigned size);
int write(int fd, const void *buffer, unsigned size);
void seek(int fd, unsigned position);
unsigned tell(int fd);
void close(int fd);
mapid_t mmap (int fd, void *addr);
void munmap (mapid_t mapping);

#endif /* userprog/syscall.h */
