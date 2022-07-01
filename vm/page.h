#include <hash.h>
#include "filesys/off_t.h"
#include "userprog/syscall.h"

struct load_info {
    struct file *file;  /* Pointer to the file */
    off_t file_offset;  /* The position of the file we start writing to 
                            the page */
    size_t read_bytes;  /* Number of bytes read from the file written to 
                            the page */
    size_t zero_bytes;  /* Number of bytes in the page which should be 
                            zeroed i.e. read_bytes subtracted from the 
                            size of a page */
    bool writable;      /* Boolean representing whether a page is read-only */
};

struct spt_elem {
    void *virtual_address;       /* key (v address of the page) */
    bool accessed_bit;           /* to use for eviction decisions */
    bool dirty_bit;              /* to see if necessary write page to memory */
    bool is_in_swap;             /* if set, then page has been written to 
                                    swap table */
    bool holds_frame;            /* to see if the page is stored in frame 
                                    table */
    int swap_index;              /* holds the pages location in the swap */
    bool loaded;                 /* to check if page has been already loaded
                                    from spt*/
    struct load_info load_info;
    mapid_t mapid;               /* only access if page_type is mapped */
    bool is_mmap;                /* whether this is a mapped file */
    int fd;                      /* File descriptor of file */   
    struct hash_elem elem;
};

bool compare_page_address (const struct hash_elem *a,
                           const struct hash_elem *b,
                           void *aux);

unsigned page_hash_func (const struct hash_elem *e, void *aux);

bool spt_init (struct hash *spt);

struct spt_elem *spt_lookup (struct hash *spt, void *address);

struct spt_elem *spt_insert (struct hash *spt, void *address);

bool spt_delete (struct hash *spt, void *address);