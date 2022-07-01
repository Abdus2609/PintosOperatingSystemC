#include "userprog/exception.h"
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include "filesys/file.h"
#include "userprog/gdt.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/syscall.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"
#include "vm/frame.h"
#include "userprog/process.h"
#include "vm/file_share.h"
#include "threads/synch.h"

#define PUSHA_DIST 32
#define MAX_STACK_PAGES 2000
static int alloced_stack_pages = 1;

struct lock movement_lock;

/* Number of page faults processed. */
static long long page_fault_cnt;

static void kill (struct intr_frame *);
static void page_fault (struct intr_frame *);

/* Registers handlers for interrupts that can be caused by user
   programs.

   In a real Unix-like OS, most of these interrupts would be
   passed along to the user process in the form of signals, as
   described in [SV-386] 3-24 and 3-25, but we don't implement
   signals.  Instead, we'll make them simply kill the user
   process.

   Page faults are an exception.  Here they are treated the same
   way as other exceptions, but this will need to change to
   implement virtual memory.

   Refer to [IA32-v3a] section 5.15 "Exception and Interrupt
   Reference" for a description of each of these exceptions. */
void
exception_init (void) 
{
  /* These exceptions can be raised explicitly by a user program,
     e.g. via the INT, INT3, INTO, and BOUND instructions.  Thus,
     we set DPL==3, meaning that user programs are allowed to
     invoke them via these instructions. */
  intr_register_int (3, 3, INTR_ON, kill, "#BP Breakpoint Exception");
  intr_register_int (4, 3, INTR_ON, kill, "#OF Overflow Exception");
  intr_register_int (5, 3, INTR_ON, kill, "#BR BOUND Range Exceeded Exception");

  /* These exceptions have DPL==0, preventing user processes from
     invoking them via the INT instruction.  They can still be
     caused indirectly, e.g. #DE can be caused by dividing by
     0.  */
  intr_register_int (0, 0, INTR_ON, kill, "#DE Divide Error");
  intr_register_int (1, 0, INTR_ON, kill, "#DB Debug Exception");
  intr_register_int (6, 0, INTR_ON, kill, "#UD Invalid Opcode Exception");
  intr_register_int (7, 0, INTR_ON, kill, "#NM Device Not Available Exception");
  intr_register_int (11, 0, INTR_ON, kill, "#NP Segment Not Present");
  intr_register_int (12, 0, INTR_ON, kill, "#SS Stack Fault Exception");
  intr_register_int (13, 0, INTR_ON, kill, "#GP General Protection Exception");
  intr_register_int (16, 0, INTR_ON, kill, "#MF x87 FPU Floating-Point Error");
  intr_register_int (19, 0, INTR_ON, kill, "#XF SIMD Floating-Point Exception");

  /* Most exceptions can be handled with interrupts turned on.
     We need to disable interrupts for page faults because the
     fault address is stored in CR2 and needs to be preserved. */
  intr_register_int (14, 0, INTR_OFF, page_fault, "#PF Page-Fault Exception");

  lock_init(&movement_lock);
}

/* Prints exception statistics. */
void
exception_print_stats (void) 
{
  printf ("Exception: %lld page faults\n", page_fault_cnt);
}

/* Handler for an exception (probably) caused by a user process. */
static void
kill (struct intr_frame *f) 
{
  /* This interrupt is one (probably) caused by a user process.
     For example, the process might have tried to access unmapped
     virtual memory (a page fault).  For now, we simply kill the
     user process.  Later, we'll want to handle page faults in
     the kernel.  Real Unix-like operating systems pass most
     exceptions back to the process via signals, but we don't
     implement them. */
     
  /* The interrupt frame's code segment value tells us where the
     exception originated. */
  switch (f->cs)
    {
    case SEL_UCSEG:
      /* User's code segment, so it's a user exception, as we
         expected.  Kill the user process.  */
      printf ("%s: dying due to interrupt %#04x (%s).\n",
              thread_name (), f->vec_no, intr_name (f->vec_no));
      intr_dump_frame (f);
      thread_exit (); 

    case SEL_KCSEG:
      /* Kernel's code segment, which indicates a kernel bug.
         Kernel code shouldn't throw exceptions.  (Page faults
         may cause kernel exceptions--but they shouldn't arrive
         here.)  Panic the kernel to make the point.  */
      intr_dump_frame (f);
      PANIC ("Kernel bug - unexpected interrupt in kernel"); 

    default:
      /* Some other code segment?  
         Shouldn't happen.  Panic the kernel. */
      printf ("Interrupt %#04x (%s) in unknown segment %04x\n",
             f->vec_no, intr_name (f->vec_no), f->cs);
      PANIC ("Kernel bug - this shouldn't be possible!");
    }
}

/* Page fault handler.  This is a skeleton that must be filled in
   to implement virtual memory.  Some solutions to task 2 may
   also require modifying this code.

   At entry, the address that faulted is in CR2 (Control Register
   2) and information about the fault, formatted as described in
   the PF_* macros in exception.h, is in F's error_code member.  The
   example code here shows how to parse that information.  You
   can find more information about both of these in the
   description of "Interrupt 14--Page Fault Exception (#PF)" in
   [IA32-v3a] section 5.15 "Exception and Interrupt Reference". */
static void
page_fault (struct intr_frame *f) 
{
  bool not_present;  /* True: not-present page, false: writing r/o page. */
  bool write;        /* True: access was write, false: access was read. */
  bool user;         /* True: access by user, false: access by kernel. */
  void *fault_addr;  /* Fault address. */

  /* Obtain faulting address, the virtual address that was
     accessed to cause the fault.  It may point to code or to
     data.  It is not necessarily the address of the instruction
     that caused the fault (that's f->eip).
     See [IA32-v2a] "MOV--Move to/from Control Registers" and
     [IA32-v3a] 5.15 "Interrupt 14--Page Fault Exception
     (#PF)". */
  asm ("movl %%cr2, %0" : "=r" (fault_addr));

  /* Turn interrupts back on (they were only off so that we could
     be assured of reading CR2 before it changed). */
  intr_enable ();
  
  /* Ensures that if lock was held before entering function, it will return
      while still holding it */
  bool already_owned_movement = true;
  if (!lock_held_by_current_thread(&movement_lock)) {
   lock_acquire(&movement_lock);
   already_owned_movement = false;
  }

  /* Count page faults. */
  page_fault_cnt++;

  /* Determine cause. */
  not_present = (f->error_code & PF_P) == 0;
  write = (f->error_code & PF_W) != 0;
  user = (f->error_code & PF_U) != 0;
   
  /* rounds the fault_addr down to the nearest page then looks up fault_addr 
     in the supplemental page table then gets a kernel page for it and
     installs it. */
  struct thread *t = thread_current(); 
  void *rnd_fault_addr = pg_round_down(fault_addr);
  struct spt_elem *spte = spt_lookup(t->spt, rnd_fault_addr);


  /* if we have an spte entry we need to lazy-load, load from swap or (re)mmap*/
  if (spte) 
  {
     /* Lazy load: 
         - get a kpage an install it using load_info set in load_segment */
    if(!spte->loaded) {
       uint8_t *kpage;

       /* Our ideal implementation for sharing:
         Before we create a new kernel page to map to, we would first check
         if the page is read-only and if so, lookup in the file sharing table 
         to see if there is already a frame allocated for that read-only page.
         It would look something like the following,

         if(!spte->load_info.writable) {
            struct share_f_elem* sf = share_f_lookup(spte->load_info.file);
            if (sf) {
               if(install_page(spte->virtual address, sf->kpage, false))
                  return;
            }
         }

         If there is something, then we use install_page to create a mapping
         between the shared kernel page and the spts user page. We would then
         increment the ft_elem's number of users member by 1.

         In process exit, when we remove entries from the frame table, we would 
         monitor the number of processes using a frame by checking the
         num_of_users member of the ft_elem struct and only free the 
         frames which have a num_of_users.
      */ 
       
       kpage = ft_alloc_page (rnd_fault_addr, PAL_USER);
       if (kpage != NULL) {
          if (install_page (spte->virtual_address, kpage, 
                            spte->load_info.writable)) {
             /* If the page is read-only, add to file sharing table */
             if (!spte->load_info.writable) {
               share_f_insert(spte->load_info.file, kpage);
             }
             frame_insert(kpage, spte->virtual_address);
             spte->holds_frame = true;

             bool already_owned_filesys = true;
             if (!lock_held_by_current_thread(&filesys_lock)) {
                lock_acquire(&filesys_lock);
                already_owned_filesys = false;
             }

             file_seek (spte->load_info.file, spte->load_info.file_offset);
             file_read (spte->load_info.file, kpage, 
                           spte->load_info.read_bytes);
             
             if (!already_owned_filesys)
               lock_release(&filesys_lock);
             
             /* Zero the rest of the page */
             memset(kpage + spte->load_info.read_bytes, 0, 
                   spte->load_info.zero_bytes);
             spte->loaded = true;
             
            if (!already_owned_movement) {
               lock_release(&movement_lock);
            }
             return;
          }
       }
    } 
    
    /* Get from swap:
        - get a kpage an install the previously evicted page */
    else if (spte->is_in_swap) {
      uint8_t *kpage = st_get_frame_back(spte);
      install_page (spte->virtual_address, kpage, 
                            spte->load_info.writable);
      spte->swap_index = INVALID_INDEX;
      spte->is_in_swap = false;

      if (!already_owned_movement) {
         lock_release(&movement_lock);
      }
      return;
    }

    /* re-map unmapped file*/
    else if (spte->is_mmap) {
       uint8_t *kpage = ft_alloc_page (rnd_fault_addr, PAL_USER);
       spte->mapid = mmap(spte->fd, kpage);
    }
  }


   /* If not in spte, check to see if we need to grow stack. Stack heuristic 
      allows push(a) instructions to grow the stack */
  else if (f->esp - PUSHA_DIST <= fault_addr && fault_addr < PHYS_BASE 
      && alloced_stack_pages < MAX_STACK_PAGES) {

     uint8_t *kpage = ft_alloc_page (rnd_fault_addr, PAL_USER);
     install_page (rnd_fault_addr, kpage, true);
     alloced_stack_pages++;

     struct spt_elem *insertee = spt_insert(t->spt, rnd_fault_addr);
     insertee->accessed_bit = true;
     insertee->dirty_bit    = true;
     insertee->is_in_swap   = false;
     insertee->holds_frame  = true;
     insertee->loaded       = true;

     if (!already_owned_movement) {
      lock_release(&movement_lock);
     }    
     return;
  }
  
  if (!already_owned_movement) {
   lock_release(&movement_lock);
  }

  /* actual page fault, i.e. invalid access*/   
  printf ("Page fault at %p: %s error %s page in %s context.\n",
          fault_addr,
          not_present ? "not present" : "rights violation",
          write ? "writing" : "reading",
          user ? "user" : "kernel");
   exit(ERROR_RETURN);
}
