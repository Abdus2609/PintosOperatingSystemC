#include "frame.h"
#include <stdio.h>
#include "threads/vaddr.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "userprog/exception.h"
#include "userprog/pagedir.h"


struct frame_table frame_table;
static struct lock frame_lock;

/* compares addresses of two ft_elems based on the kernel virtual address */
bool compare_frame_address(const struct hash_elem *a,
                           const struct hash_elem *b,
                           void *aux UNUSED) 
{
    return hash_entry(a,struct ft_elem, elem)->kpage <
           hash_entry(b,struct ft_elem, elem)->kpage;
}

/* defining haash function based on kernel virtual address */
unsigned frame_hash_func (const struct hash_elem *e, void *aux UNUSED) 
{
    struct ft_elem *f = hash_entry(e,struct ft_elem, elem);
    return hash_int((int) f->kpage);
}

/* initializing the hash struct and setting the initial size to 0 */
bool frame_table_init (void) 
{
    lock_init(&frame_lock);
    frame_table.victim_cursor = get_pool_base();
    return hash_init(&frame_table.table, &frame_hash_func, 
                        &compare_frame_address, NULL); 
}

/* looks up an entry based on the kernel virtual address */
struct ft_elem *ft_lookup (void *kpage) 
{
    struct ft_elem *fte = malloc(sizeof(struct ft_elem));
    fte->kpage = kpage;
    if (!lock_held_by_current_thread(&frame_lock))
        lock_acquire(&frame_lock);
    struct hash_elem* found_elem = hash_find(&frame_table.table, &fte->elem);
    lock_release(&frame_lock);
    
    free(fte);

    if(!found_elem) 
    {
        return NULL;
    }

    struct ft_elem *fe = hash_entry(found_elem, struct ft_elem, elem);
    return fe;
}

/* inserts a mapping from kernel virtual address kpage to user page upage */
bool frame_insert (void *kpage, void *upage) 
{
    struct ft_elem *fte = malloc(sizeof(struct ft_elem));
    
    fte->kpage = kpage;
    fte->upage = upage;
    fte->owner = thread_current();
    fte->num_users = 1;
    
    if (!lock_held_by_current_thread(&frame_lock))
        lock_acquire(&frame_lock);
    struct hash_elem *he = hash_insert(&frame_table.table, &fte->elem);
    lock_release(&frame_lock);
    
    if (!he) {
        frame_table.size++;
        return true;
    }
    
    free(fte); 
    return false;
}

/* This function does not clear page table entries, palloc_free_page must be 
    called after this function if that behaviour is required */
bool free_frame (void *kpage) 
{
    struct ft_elem *fte = ft_lookup(kpage);
    
    if (!lock_held_by_current_thread(&frame_lock))
        lock_acquire(&frame_lock);    
    
    /* Remove from hash table */
    struct hash_elem *he = hash_delete(&frame_table.table, &fte->elem);
    
    lock_release(&frame_lock);
    
    if (he) {
        return true;
    } 
    
    return false;
}

void frame_increment_users (void *kpage) {
    struct ft_elem *fte = ft_lookup(kpage);
    fte->num_users++;
}

void frame_decrement_users (void *kpage) {
    struct ft_elem *fte = ft_lookup(kpage);
    fte->num_users--;
}

/* returns a virtual page from the kernel if there is a free page and if
   there are no free pages, evicts a frame and returns the newly freed page. */
void *ft_alloc_page (void *upage, enum palloc_flags flags) 
{   
    /* Commented code is how we intended to implement further synchronisation
        between page faults and page eviction */

    // bool already_owned_movement = true;
    // if (!lock_held_by_current_thread(&movement_lock)) {
    //     lock_acquire(&movement_lock);
    //     already_owned_movement = false;
    // }
   
    lock_acquire(&palloc_lock);

    void* kpage = palloc_get_page(flags);
    if (kpage != NULL) 
    {
        frame_insert (kpage, upage);
        lock_release(&palloc_lock);

        // if (!already_owned_movement) {
        //     lock_release(&movement_lock);
        // }

        return kpage;
    }

    /* no frame available so try to evict one */
    while (true) 
    {
        frame_table.victim_cursor += PGSIZE;
        frame_table.victim_cursor = pg_frm_pool(frame_table.victim_cursor) ? 
                                        frame_table.victim_cursor : 
                                        get_pool_base ();
        
        struct ft_elem *victim = ft_lookup(frame_table.victim_cursor);  
        void* upage = victim->upage;

        /* If the accesed bit is 1, frame has been revently used, so we set it 
            to zero and give it a second chance */
        if (pagedir_is_accessed(victim->owner->pagedir, victim->upage)) 
        {
            pagedir_set_accessed(victim->owner->pagedir, victim->upage, false);
        }

        /* otherwise we will evict */ 
        else 
        {
          struct spt_elem *victim_spte = spt_lookup(victim->owner->spt, upage);

            /* if victim is a mmap file, write back to file system*/
            if (victim_spte->is_mmap) {
                munmap(victim_spte->mapid);
                victim->owner = thread_current();
                
                lock_release(&palloc_lock);

                // if (!already_owned_movement) {
                //     lock_release(&movement_lock);
                // }

                return victim->kpage;
            }

            /* put evictee in swap table and remove from frame table */            
            victim_spte->swap_index = put_in_swap(victim->kpage);
            victim_spte->is_in_swap = true;
            victim->upage = upage;
            
            free_frame(victim->kpage);
            frame_insert(victim->kpage, upage);
            pagedir_clear_page(victim->owner->pagedir, upage);
            victim->owner = thread_current();
            
            lock_release(&palloc_lock);

            // if (!already_owned_movement) {
            //     lock_release(&movement_lock);
            // }
            
            return victim->kpage;
        }
    }

    // if (!already_owned_movement) {
    //     lock_release(&movement_lock);
    // }
}

void *st_get_frame_back (struct spt_elem *spte) 
{
    /* gets a page, copies swap contents into page, removes contents in swap */
    void *kpage = ft_alloc_page(spte->virtual_address, PAL_USER);
    swpblk_read_page(spte->swap_index, kpage);
    remove_from_swap(spte->swap_index);
    
    spte->is_in_swap = false;
    spte->swap_index = INVALID_INDEX;
    
    return kpage;
}
