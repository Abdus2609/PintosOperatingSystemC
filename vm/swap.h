#include <bitmap.h>
#include "../devices/block.h"
#include "../threads/vaddr.h"

struct swap_block {
    struct block *block;    /* the BLOCK_SWAP that will store evicted pages */
    struct bitmap *bitmap;  /* a bitmap to track which sectors of the swap
                               are currently occupied */
};

void initialize_swap_block(void);

int put_in_swap(void* page);

void remove_from_swap(int page_idx);

void swpblk_read_page(int page_idx, void *receiver);