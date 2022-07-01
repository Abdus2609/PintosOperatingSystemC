#include "file_share.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "filesys/inode.h"
#include "filesys/file.h"

struct hash shared_files;

static struct lock share_lock;

/* compares addresses of two shared_elems based on their addresses */
bool compare_file_address (const struct hash_elem *a,
                           const struct hash_elem *b,
                           void *aux UNUSED) 
{
    struct shared_elem* sf_a = hash_entry(a, struct shared_elem, elem);
    struct shared_elem* sf_b = hash_entry(b, struct shared_elem, elem);
    return ((int) sf_a->file->inode * sf_a->file->pos) <
           ((int) sf_b->file->inode * sf_b->file->pos);
}

/* defining hash function based on kernel virtual address */
unsigned share_f_hash_func (const struct hash_elem *e, void *aux UNUSED) 
{
    struct shared_elem *s = hash_entry(e,struct shared_elem, elem);
    return hash_int((int) s->file->inode * s->file->pos);
}

bool share_f_table_init (void) 
{
    lock_init(&share_lock);
    return hash_init(&shared_files, &share_f_hash_func,
                     &compare_file_address, NULL); 
}

/* Look up in hash table to retrieve frame address (kernel page address) */
struct shared_elem *share_f_lookup (struct file *file) 
{
    struct shared_elem *s = malloc(sizeof(struct shared_elem));
    s->file = file;
    
    if (!lock_held_by_current_thread(&share_lock))
        lock_acquire(&share_lock);
    struct hash_elem* found_elem = hash_find(&shared_files, &s->elem);
    lock_release(&share_lock);
    
    free(s);
    
    if(!found_elem)
        return NULL;
    
    return hash_entry(found_elem, struct shared_elem, elem);
}

/* Insert new shared_elem into hash table */
bool share_f_insert (struct file *file, void *addr_in_frame) 
{
    struct shared_elem *s = malloc(sizeof(struct shared_elem));
    s->file = file;
    s->addr_in_frame = addr_in_frame;
    
    if (!lock_held_by_current_thread(&share_lock))
        lock_acquire(&share_lock);
    struct hash_elem *he = hash_insert(&shared_files, &s->elem);
    lock_release(&share_lock);
    
    if (!he) {
        return true;
    } 
    
    return false;
}

/* Remove shared_elem corresponding to file from hash table */
bool remove_shared_file (struct file *file) 
{
    struct shared_elem *s = share_f_lookup(file);
    
    if (!lock_held_by_current_thread(&share_lock))
        lock_acquire(&share_lock);
    struct hash_elem *he = hash_delete(&shared_files, &s->elem);
    lock_release(&share_lock);
    
    if (he) {
        return true;
    } 
    
    return false;
}