/* The idea is to first check if the page is writable,
If it is then its none of our business.

But, if it is then we need to put it in a global list,
the list contains shared_elems.
Once a process is ready to actually load a file that is read-only,
it will do a spt_lookup as usual.
It will also check the global table and see if the file has already been loaded
(i.e the addr_in_frame is not null or its not there at all).
If it has then then it will map its page the to kpage provided in the global 
struct. Otherwise it will load as usual and set the addr_in_frame to the address 
that it mapped the page to.*/
#include <hash.h>
#include <stdbool.h>
#include "filesys/off_t.h"
#include "filesys/file.h"

extern struct hash shared_files;

struct shared_elem {
    struct file *file;      /* the file that we want to share */
    void *addr_in_frame;    /* Kernel page address - the frame shared by
                                all users */
    off_t offset;           /* The start position of the file written to the
                                page */     
    struct hash_elem elem;
};

bool compare_file_address(const struct hash_elem *a,
                           const struct hash_elem *b,
                           void *aux);

unsigned share_f_hash_func (const struct hash_elem *e, void *aux);

bool share_f_table_init(void);

struct shared_elem *share_f_lookup(struct file *file);

bool share_f_insert (struct file *file, void *addr_in_frame);

bool remove_shared_file (struct file *file);

