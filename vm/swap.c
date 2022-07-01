#include "swap.h"
#include "threads/synch.h"

struct swap_block swap_block;

static struct lock swap_lock;

/* initializes swap block */                             
void initialize_swap_block(void) {
    lock_init(&swap_lock);
    swap_block.block = block_get_role(BLOCK_SWAP);
    swap_block.bitmap = bitmap_create(block_size(swap_block.block));
}

/* writes the page into swap and returns the index that it was written to and
   also updates the bitmap */
int put_in_swap(void* page) 
{
    if (!lock_held_by_current_thread(&swap_lock)) {
        lock_acquire(&swap_lock);
    }
    int cursor = bitmap_scan_and_flip(swap_block.bitmap, 0, 8, 0);
    void* page_cursor = page;
    for (int i = 0; i < 8; i++) {
        block_write(swap_block.block, cursor, page_cursor);
        cursor++;
        page_cursor += PGSIZE / 8;
    }

    lock_release(&swap_lock);
    
    /* Subtract 8 to go the the beginning of the section written to then divide 
        by 8 to get a page index rather than a block index */
    return (cursor - 8) / 8;
}

/* removes page by updating the bitmap to 0 where the page is so that any
   new entry can be written in its place as it will see that slot as free */

void remove_from_swap(int page_idx) 
{
    if (!lock_held_by_current_thread(&swap_lock)) {
        lock_acquire(&swap_lock);
    }
    int cursor = page_idx * 8;
    bitmap_set_multiple(swap_block.bitmap, cursor, 8, 0);
    lock_release(&swap_lock);
}

/* reads a page at the given index into the given receiver buffer */

void swpblk_read_page(int page_idx, void *receiver) 
{
    if (!lock_held_by_current_thread(&swap_lock)) {
        lock_acquire(&swap_lock);
    }
    
    int cursor = page_idx * 8;
    void *receiver_cursor = receiver;
    for (int i = 0; i < 8; i++) {
        block_read(swap_block.block, cursor, receiver_cursor);
        receiver_cursor += PGSIZE / 8;
        cursor++;
    }

    lock_release(&swap_lock);
}