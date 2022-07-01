#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "devices/shutdown.h"
#include "devices/input.h"
#include "threads/interrupt.h"
#include "threads/synch.h"
#include "threads/malloc.h"
#include "filesys/file.h"
#include "userprog/process.h"
#include "threads/vaddr.h"
#include <hash.h>
#include "userprog/pagedir.h"
#include <string.h>
#include "vm/page.h"

static void *function_table[TOTAL_NUM_SYSCALLS];

static bool check_address (void *address, enum access_type type);
static struct file_elem* search_for_file (int key, enum search_type type);
static struct file_elem* create_file_elem (struct file* file, bool mapped,
                                            void *mapped_addr);

static void syscall_handler (struct intr_frame* f);

struct lock filesys_lock;

static struct lock map_lock;

/* Check the address is in the correct space and depending on the access type
    enum, check whether the corresponding page is NULL.
    The access type enum is there to distinguish the cases of when we would
    want the page to be NULL e.g. for a buffer that we would want to store
    the contents of a file in - it needs to be empty */
static bool check_address (void *address, enum access_type type) 
{
  if (!is_user_vaddr(address))
    exit(ERROR_RETURN);
  if (type == OTHER && !pagedir_get_page(thread_current()->pagedir, address)) 
  {
    return false;
  }

  return true;
}

/* Search for a file given a key in the threads list of files. The key
    can be either a file descriptor or mapping id, specified by the type
    arg, in order to encompass the two types of file search we need 
    (regular file search or mapped file search) */
static struct file_elem* search_for_file (int key, enum search_type type)
{
  struct thread* t = thread_current();
  struct list_elem* e;

  for (e = list_begin(&t->files); e != list_end(&t->files); e = list_next(e))
  {
    struct file_elem* file_elem = list_entry(e, struct file_elem, elem);
    if ((type == FILE_DESC && file_elem->fd == key) 
          || (type == MAP_ID && file_elem->mapid == key)) {
            return file_elem;
    }
  }

  return NULL;
}

/* Create a file elem struct - mapped-file specific members to assign if mapped 
    argument is true */
static struct file_elem* create_file_elem (struct file* file, bool mapped,
                                            void *mapped_addr) 
{
  struct thread* t = thread_current();
  
  struct file_elem* file_elem = malloc(sizeof(struct file_elem));
  if (!file_elem) {
    exit(ERROR_RETURN);
  }

  file_elem->file = file;
  file_elem->fd = t->next_fd++;
  file_elem->mapped = mapped;
  if (mapped) {  
    file_elem->mapid = t->next_mapid++;
    file_elem->mapped_addr = mapped_addr;
  }

  list_push_back(&t->files, &file_elem->elem);

  return file_elem;
}

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&filesys_lock);
  lock_init(&map_lock);

  function_table[SYS_HALT] = &halt;
  function_table[SYS_EXIT] = &exit;
  function_table[SYS_EXEC] = &exec;
  function_table[SYS_WAIT] = &wait;
  function_table[SYS_CREATE] = &create;
  function_table[SYS_REMOVE] = &remove;
  function_table[SYS_OPEN] = &open;
  function_table[SYS_FILESIZE] = &filesize;
  function_table[SYS_READ] = &read;
  function_table[SYS_WRITE] = &write;
  function_table[SYS_SEEK] = &seek;
  function_table[SYS_TELL] = &tell;
  function_table[SYS_CLOSE] = &close;
  function_table[SYS_MMAP] = &mmap;
  function_table[SYS_MUNMAP] = &munmap;
}

static void
syscall_handler (struct intr_frame *f) 
{

  int *esp = f->esp;
  if (!check_address(esp, OTHER))
    exit(ERROR_RETURN);
  int syscall_number = *esp;

  esp++;

  int arg1 = check_address(esp, OTHER) ? *esp : (int) NULL;
  int arg2 = check_address(esp + 1, OTHER) ? *(esp + 1) : (int) NULL;
  int arg3 = check_address(esp + 2, OTHER) ? *(esp + 2) : (int) NULL;

  int (*function) (int, int, int) = function_table[syscall_number];

  f->eax = (*function) (arg1, arg2, arg3);
}


void halt (void) 
{
  shutdown_power_off();
}

void exit (int status) 
{
  struct thread *t = thread_current(); 
  struct list_elem *e;

  if (lock_held_by_current_thread(&map_lock)) {
    lock_release(&map_lock);
  }
  if (!lock_held_by_current_thread(&filesys_lock)) {
    lock_acquire(&filesys_lock);
  }

  for (e = list_begin(&t->files); e != list_end(&t->files); e = list_next(e)) 
  {
    struct file_elem* file_elem = list_entry(e, struct file_elem, elem);
    if (file_elem->mapped) {
      munmap(file_elem->mapid);
    }
    file_close(file_elem->file);
    list_remove(&file_elem->elem);
  }

  if (lock_held_by_current_thread(&filesys_lock))
    lock_release(&filesys_lock);

  t->exit_status = status;

  char *token, *save_ptr;
  token = strtok_r (t->name, " ", &save_ptr);

  printf ("%s: exit(%d)\n", token, status);
  thread_exit();
}

pid_t exec (const char *cmd_line)
{
  if (!check_address((void *) cmd_line, OTHER)) {
    exit(ERROR_RETURN);
  }

  tid_t t_status = process_execute(cmd_line);
  
  return t_status;
}

int wait (pid_t pid) 
{
  return process_wait(pid);
}

bool create(const char *file, unsigned initial_size) 
{
  if (!file || !check_address((void *) file, OTHER)) {
    exit(ERROR_RETURN);
  }
  
  lock_acquire(&filesys_lock);
  bool success = filesys_create(file, initial_size);
  lock_release(&filesys_lock);
  
  return success;
}

bool remove (const char* file) 
{
  if (!file) {
    return false;
  }

  if (!check_address((void *) file, OTHER)) {
    exit(ERROR_RETURN);
  }

  lock_acquire(&filesys_lock);
  bool success = filesys_remove(file);
  lock_release(&filesys_lock);

  return success;
}

int open (const char *file) 
{
  if (!file || !check_address((void *) file, OTHER)) {
    exit(ERROR_RETURN);
  }

  struct file *o_file;
  if (!lock_held_by_current_thread(&filesys_lock))
    lock_acquire(&filesys_lock);

  o_file = filesys_open(file);
  
  lock_release(&filesys_lock);

  if (!o_file) {
     return ERROR_RETURN;
  }

  struct file_elem *file_elem = create_file_elem(o_file, false, NULL);
  
  return file_elem->fd;
}

int filesize (int fd) 
{
  struct file_elem* file_elem;
  
  file_elem = search_for_file(fd, FILE_DESC);
  
  if (!file_elem) {
    return 0;
  }
  
  if (!lock_held_by_current_thread(&filesys_lock))
    lock_acquire(&filesys_lock);
  int size = file_length(file_elem->file);
  lock_release(&filesys_lock);

  return size;
}

int read (int fd, void* buffer, unsigned size) 
{
  if (!(check_address(buffer, READ) && check_address(buffer + size, READ))) {
    exit(ERROR_RETURN);
  }

  struct spt_elem* spte = spt_lookup(thread_current()->spt, pg_round_down(buffer));

  if (spte) {
    if (!spte->load_info.writable) {
      exit(ERROR_RETURN);
    }
  }
  
  if (fd == STDOUT_FD) {
    /* Cannot read from standard output */
    return ERROR_RETURN;
  }
  
  if (fd == STDIN_FD) {
    for (int i = 0; i < (int) size; i++) {
      *((char *) buffer + i) = (char) input_getc();
    }

    return size;
  }

  struct file_elem* file_elem;
  
  file_elem = search_for_file(fd, FILE_DESC);
  
  if (!file_elem) {
    return ERROR_RETURN;
  }
  
  if (!lock_held_by_current_thread(&filesys_lock))
    lock_acquire(&filesys_lock);
  int num_bytes_read = file_read(file_elem->file, buffer, size);
  lock_release(&filesys_lock);

  if ((unsigned) num_bytes_read < size) {
    return 0;
  }

  return num_bytes_read;
}

int write (int fd, const void* buffer, unsigned size)
{
  if (fd == STDIN_FD)
    /* Cannot write to standard input */
    return ERROR_RETURN;

  if (fd == STDOUT_FD) {
    putbuf(buffer, size);
    return size;
  }

  struct file_elem* file_elem = search_for_file(fd, FILE_DESC);

  if (!file_elem)
    exit(ERROR_RETURN);

  enum access_type type = file_elem->mapped ? WRITE_M : OTHER; 

  if (!(check_address(buffer, type) && check_address(buffer + size, type)))
    exit(ERROR_RETURN);

  if (!lock_held_by_current_thread(&filesys_lock))
    lock_acquire(&filesys_lock);
  int num_bytes_written = file_write(file_elem->file, buffer, size);
  lock_release(&filesys_lock);

  return num_bytes_written;
}

void seek (int fd, unsigned position) 
{
  struct file_elem* file_elem;

  file_elem = search_for_file(fd, FILE_DESC);

  if (!file_elem)
    exit(ERROR_RETURN);

  if (!lock_held_by_current_thread(&filesys_lock))
    lock_acquire(&filesys_lock);
  file_seek(file_elem->file, position);
  lock_release(&filesys_lock);
}

unsigned tell (int fd) 
{
  struct file_elem* file_elem;

  file_elem = search_for_file(fd, FILE_DESC);

  if (!file_elem)
    exit(ERROR_RETURN);
  
  lock_acquire(&filesys_lock);
  int position = file_tell(file_elem->file);
  lock_release(&filesys_lock);

  return position;
}

void close (int fd) 
{
  struct file_elem* file_elem;

  file_elem = search_for_file(fd, FILE_DESC);
  
  if (fd < FIRST_AVAILABLE_FD || !file_elem) {
    exit(ERROR_RETURN);
  }

  if (!lock_held_by_current_thread(&filesys_lock))
    lock_acquire(&filesys_lock);
  file_close(file_elem->file);
  list_remove(&file_elem->elem);
  free(file_elem);
  lock_release(&filesys_lock);
}

mapid_t mmap (int fd, void *addr) 
{
  /* Check address is page-aligned, file descriptor is valid, address is not
      zero and address is not in the pages reserved for stack */
  if ((int) addr % PGSIZE != 0 || fd < FIRST_AVAILABLE_FD || addr == 0
    || addr >= BOTTOM_OF_STACK) 
  {
    return ERROR_RETURN;
  }

  /* Ensures that if we held the lock before entering the function, we 
      will still have it when returning */
  bool already_owned = true;
  if (!lock_held_by_current_thread(&map_lock)) {
    lock_acquire(&map_lock);
    already_owned = false;
  }
  
  /* Search for original file in thread's list of files */
  struct file_elem* file_elem = search_for_file(fd, FILE_DESC);
  if (!file_elem)
    return ERROR_RETURN;

  /* Obtain a separate reference to the file */
  lock_acquire(&filesys_lock);
  struct file* m_file = file_reopen(file_elem->file);
  lock_release(&filesys_lock);

  int fsize = filesize(fd);
  int num_pages = fsize % PGSIZE == 0 ? fsize / PGSIZE : (fsize / PGSIZE) + 1;

  int read_bytes = fsize;
  int zero_bytes = (num_pages * PGSIZE) - read_bytes;
  void* curr_addr = addr;

  /* Create a file_elem struct for mapped file */
  struct file_elem* m_file_elem = create_file_elem(m_file, true, addr);
  m_file_elem->mem_file_size = fsize;

  /* Lazily load the mapped file */
  if (!load_segment(m_file, 0, curr_addr, read_bytes, zero_bytes, true, true, 
      m_file_elem->fd)) 
  {
    close(m_file_elem->fd);  
    if (!already_owned)
      lock_release(&map_lock);
  
    return ERROR_RETURN;
  }

  if (!already_owned) {
    lock_release(&map_lock);
  }

  return m_file_elem->mapid;
}

void munmap (mapid_t mapping) 
{
  struct thread* t = thread_current();
  struct file_elem* m_file_elem = search_for_file(mapping, MAP_ID);
  
  /* Check mapped file exists and the file's mapid is not 0 which indicates
      it is not a mapped file */
  if (!m_file_elem || mapping < FIRST_AVAILABLE_MAPID)
    exit(ERROR_RETURN);

  if (!m_file_elem->mapped)
    return;

  lock_acquire(&map_lock);
  
  int fsize = m_file_elem->mem_file_size;
  int num_pages = fsize % PGSIZE == 0 ? fsize / PGSIZE : (fsize / PGSIZE) + 1;
  void *addr = m_file_elem->mapped_addr;
  
  /* Iterate through every page of mapped file in supplemental page table */
  for (int pno = 0; pno < num_pages; pno++)
  {
    /* Only write back to the file if the page has been written to by the
        process - dirty bit is true */
    if (pagedir_is_dirty(t->pagedir, addr)) 
    {  
      /* Seek used to start writing from the correct position in the file */
      seek(m_file_elem->fd, pno * PGSIZE);
      write(m_file_elem->fd, addr, PGSIZE);
    }

    /* Remove the mapped file's content from the page table and the 
        supplemental page table */  
    pagedir_clear_page(t->pagedir, addr);
    spt_delete(t->spt, addr);
    addr += PGSIZE;
  }

  /* Set mapped to false so in exit syscall, munmap is not called on this 
      file */
  m_file_elem->mapped = false;
  lock_release(&map_lock);
}
