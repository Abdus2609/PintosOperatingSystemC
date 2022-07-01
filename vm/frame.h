#include <hash.h>
#include <bitmap.h>
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "vm/swap.h"
#include "vm/page.h"

#define MAX_FRAMES ((size_t) 367)
#define INVALID_INDEX -1

typedef uintptr_t frame_no;

struct frame_table {
    struct hash table;
    int size;
    void *victim_cursor;
};

extern struct frame_table frame_table;

// frame table (address) -> (page*)
struct ft_elem {
    void* kpage;            /* kernel page stored in frame */
    void* upage;            /* user page stored in frame */
    struct thread *owner;   /* will need to get the supplementary page table */
    int num_users;          /* Number of processes sharing this frame */
    struct hash_elem elem;
};

bool compare_frame_address(const struct hash_elem *a,
                           const struct hash_elem *b,
                           void *aux);
unsigned frame_hash_func (const struct hash_elem *e, void *aux);

bool frame_table_init(void);

struct ft_elem *ft_lookup(void *kpage);

bool frame_insert (void *kpage, void *upage);

bool free_frame (void *kpage);

void* ft_alloc_page (void *upage, enum palloc_flags flags);

void* st_get_frame_back(struct spt_elem *spte);

void frame_increment_users(void *kpage);

void frame_decrement_users(void *kpage);