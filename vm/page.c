#include "page.h"
#include "threads/malloc.h"

/* Comparing function for supplemental page table elements */
bool compare_page_address (const struct hash_elem *a,
                          const struct hash_elem *b,
                          void *aux UNUSED) 
{
    return hash_entry(a, struct spt_elem, elem)->virtual_address
         < hash_entry(b, struct spt_elem, elem)->virtual_address;
}

/* Hashing function for supplemental page table elements */
unsigned page_hash_func (const struct hash_elem *e, void *aux UNUSED) 
{
    struct spt_elem *spte = hash_entry(e, struct spt_elem, elem);
    return hash_int((int) spte->virtual_address);
}

/* Initalise a threads supplemental page table */
bool spt_init (struct hash *spt)
{
    return hash_init(spt, &page_hash_func, &compare_page_address, NULL);
}

/* Look up a supplemental page table element using a virtual address */
struct spt_elem *spt_lookup (struct hash *spt, void *page)
{
    struct spt_elem *e = malloc(sizeof(struct spt_elem));
    e->virtual_address = page;
    struct hash_elem* found_elem = hash_find(spt, &e->elem);

    if (!found_elem)
    {
        free(e);
        return NULL;
    }

    free(e);
    struct spt_elem *res = hash_entry(found_elem, struct spt_elem, elem);
    
    return res;
}

/* Insert a supplemental page table element into the thread's table */
struct spt_elem *spt_insert (struct hash *spt, void *page) 
{
    struct spt_elem *e = malloc(sizeof(struct spt_elem));
    e->virtual_address = page;
    struct hash_elem *he = hash_insert(spt, &e->elem);
    
    if (!he) {
        return e;
    }
    
    return NULL;
}

/* Remove a supplemental page table element from the thread's table */
bool spt_delete (struct hash *spt, void *page) 
{
    struct spt_elem* e = spt_lookup(spt, page);
    if (!e)
        return false;

    struct hash_elem *he = hash_delete(spt, &e->elem);
    
    if (!he) {
        return false;
    }
    
    return true;
}