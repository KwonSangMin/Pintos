#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "../lib/kernel/bitmap.h"
#include "../devices/block.h"
static thread_func start_process NO_RETURN;
extern struct lock file_sys_lock;
static bool load (const char *cmdline, void (**eip) (void), void **esp);
extern struct list frame_table;
extern struct bitmap* swap_disk_bitmap;
extern struct block* swap_disk;
extern struct lock load_lock;
/* Starts a new threa running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name) 
{
  char *fn_copy;
  tid_t tid;
  
  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy (fn_copy, file_name, PGSIZE);
  /* Create a new thread to execute FILE_NAME. */
  size_t leng;
  leng=strcspn(file_name, " ");
  char FILE_NAME_ONLY[14];//pintos limit 14
  char *PN=FILE_NAME_ONLY;
  memcpy(FILE_NAME_ONLY,file_name,leng);
  FILE_NAME_ONLY[leng]= '\0';//FILE_NAME_ONLY store just nam
   tid = thread_create (PN, PRI_DEFAULT, start_process, fn_copy);//parent, child 
  struct thread* cur=thread_current();   
//  list_push_back(&(cur->child_list), &((ret_thread(tid))->chelem));
  cur->child_num++;
  sema_down(&(thread_current()->load_child));
   if (tid == TID_ERROR)
    palloc_free_page (fn_copy); 
  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *file_name_)//child excute this function not parent
{
  char *file_name = file_name_;
  struct intr_frame if_;
  bool success;
  struct thread* cur=thread_current();
  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  char *token, *save_ptr;
  int argc=0;
  char* argv[32];//limit 128bytes
  for(token=strtok_r(file_name," ",&save_ptr);token!=NULL;token=strtok_r(NULL," ",&save_ptr))
  {
    argv[argc++]=token;
  }//parsing arguments argv[0] = file_name argv[1] = arg_1 argv[2] = arg_2
   success = load (argv[0], &if_.eip, &if_.esp);//user program load on memory and stack set up
  sema_up(&((cur->parent_ptr)->load_child));
  if(!success){
  cur->parent_ptr->load_state=-1; 
  thread_exit();
  }
  int index = argc-1;
  int word_check=0;
  for(;index>=0;index--)
  {
    int len=strlen(argv[index]);
    int inc=len-1;
    if_.esp=if_.esp-1;
    *(char*)if_.esp='\0';
    for(;len>0;len--)
    {
      char* ptr=argv[index];
      if_.esp=if_.esp-1;
      *(char*)if_.esp=*(ptr+inc);
      inc--;
      word_check++;
    }
    word_check++;
  }//argv right to left push on stack 
  if(word_check%4!=0)
  {
    if_.esp=if_.esp-(4-(word_check%4));
    *(uint8_t*)if_.esp=0;
   }//page_align
  index = argc-1;
  if_.esp=if_.esp-4;
  *(char**)if_.esp=NULL;
  void* initial_esp=PHYS_BASE;
  int loc=0;
  for(;index>=0;index--)
  {
    if_.esp=if_.esp-4;
    *(char**)if_.esp=(initial_esp-1-strlen(argv[index])-loc);
    loc+=strlen(argv[index])+1;
  }
  //push arg after call  
  if_.esp=if_.esp-4;
  *(char***)if_.esp=(if_.esp+4);//argv
  if_.esp=if_.esp-4;
  *(int*)if_.esp=argc;//argc
  if_.esp=if_.esp-4;
  *(void**)if_.esp=NULL;
  palloc_free_page (file_name);
  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();

}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid UNUSED) //child_tid check
{
  struct thread* cur=thread_current();
 struct thread* Target_child=ret_thread(child_tid);
  if(Target_child==NULL||Target_child->parent_ptr!=thread_current())
 {return -1;}//child_tid is not child of the process
  if(Target_child->wp_sema==1)
 {  int ret=Target_child->exit_state;
   sema_up(&Target_child->wait_parent);
  sema_init(&cur->wait_child,0);
  Target_child->is_parent_waiting=1;
  sema_down(&cur->wait_child);
  return ret;}
  else
  {
    sema_init(&cur->wait_child,0);
    Target_child->is_parent_waiting=1;
    sema_down(&cur->wait_child);
    return cur->exit_state;
  }
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;
  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  file_close(cur->Excuting_file);
  for(;cur->opening_num>1;cur->opening_num--)//close all file
  {
    close(cur->opening_num);
  }
  while(!list_empty(&cur->memory_map_list))
  {
    struct memory_map_entry* mm = list_entry(list_pop_front(&cur->memory_map_list),struct memory_map_entry, mm_elem);
    list_push_front(&cur->memory_map_list,&mm->mm_elem);
    munmap(mm->mapid);
  }//mmap delete
  pd = cur->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp)
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();
  
  while(!(lock_try_acquire(&file_sys_lock)));
  /* Open executable file. */
  file = filesys_open(file_name);  
  t->Excuting_file=file;
  if (file == NULL) 
    {
      lock_release(&file_sys_lock);
      printf ("load: %s: open failed\n", file_name);
      goto done; 
    }
  file_deny_write(file);
  lock_release(&file_sys_lock);
  hash_init(&t->supple_page,page_hash,page_less,NULL);
 /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp))
    goto done;
  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not*/
    return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */

static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);
  file_seek (file, ofs);
  struct thread* cur=thread_current();
  while (read_bytes > 0 || zero_bytes > 0) //4KB load per loop
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      struct page_table_entry* p=(struct page_table_entry*)malloc(sizeof(struct page_table_entry));
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;
      p->Ref_file=file;
      p->read_bytes=page_read_bytes;
      p->zero_bytes=page_zero_bytes;
      p->addr=upage;
      p->ofs=ofs;
      p->writable=writable;      
      p->mapid=0;
      p->swaped=0; 
     /* Get a page of memory. */
      hash_insert(&cur->supple_page,&p->h_elem);
      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
      ofs+=page_read_bytes;
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp) 
{
  uint8_t *kpage;
  bool success = false;

  kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  if (kpage != NULL) 
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success)
        *esp = PHYS_BASE;
      else
        palloc_free_page (kpage);
    }
  struct thread* c=thread_current();
  c->esp=PHYS_BASE-PGSIZE;
  c->stack_num=1;
//  struct frame_entry* f=(struct frame_entry*)malloc(sizeof(struct frame_entry));
//  f->frame_addr=kpage;
//  f->writable=1;
//  f->owner=c;
//  list_push_back(&frame_table,&f->frame_elem);

//  printf("PHYS_BASE: %x esp : %x\n",PHYS_BASE,c->esp);
  struct page_table_entry* p=(struct page_table_entry*)malloc(sizeof(struct page_table_entry));
  p->addr=0xc0000000-PGSIZE;
  p->writable=1;
  p->read_bytes=0;
  p->zero_bytes=PGSIZE;  
  p->stack_=1; 
  p->swaped=0;
  hash_insert(&c->supple_page,&p->h_elem);
//  f->own_page=p;
//  list_push_back(&frame_table,&f->frame_elem);
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}
bool load_from_file(struct page_table_entry* cur)
{
  while(!lock_try_acquire(&load_lock));  
      uint8_t *kpage = palloc_get_page (PAL_USER); 
      if(kpage==NULL)
      {
        //printf("Size of frame %d, KPAGE IS NULL WHEN ADDR :%x\n",list_size(&frame_table),cur->addr);
        if(swap_disk==NULL){
        swap_disk_bitmap=bitmap_create(8192);
        swap_disk=block_get_role(BLOCK_SWAP);
        }
        if(!bitmap_all(swap_disk_bitmap,0,8191))
        {
          struct frame_entry* victim=list_entry(list_head(&frame_table),struct frame_entry,frame_elem);
          while(1)//accessed is 0 finding
          {
            victim=list_entry(list_next(&victim->frame_elem),struct frame_entry, frame_elem);
            if(victim==list_entry(list_end(&frame_table),struct frame_entry,frame_elem))
            {
              victim=list_entry(list_begin(&frame_table),struct frame_entry,frame_elem);
              break;
            } 
            if(pagedir_is_accessed(victim->owner->pagedir,victim->own_page->addr))
            {
              pagedir_set_accessed(victim->owner->pagedir,victim->own_page->addr,0);
            }
            else
            {
              break;
            }
          }
          int start; 
         if(pagedir_is_dirty(victim->owner->pagedir,victim->own_page->addr))
          {
           // block_write(swap_disk,start,(victim->own_page->addr)+BLOCK_SECTOR_SIZE*i);
           // printf("pagedir_is_dirty\n");
           // pagedir_set_dirty(victim->owner->pagedir,victim->own_page->addr,0);
           }// file_write_at(victim->own_page->Ref_file,victim->own_page->addr,victim->own_page->read_bytes,victim->own_page->ofs);
            int i;
            for(i=0;i<8;i++)
            { 
              start=bitmap_scan_and_flip(swap_disk_bitmap,0,1,0);
              if(i==0)victim->own_page->sec_num=start;
              block_write(swap_disk,start,(victim->own_page->addr)+BLOCK_SECTOR_SIZE*i);
            }
              victim->own_page->swaped=1;
           
          victim->own_page->is_loaded=0;
          palloc_free_page(pagedir_get_page(victim->owner->pagedir,victim->own_page->addr));
          pagedir_clear_page(victim->owner->pagedir,victim->own_page->addr);
          list_remove(&victim->frame_elem);
          free(victim);
          kpage=palloc_get_page(PAL_USER);
        }
      } //VICTIM swap out to swap disk , kpage is victim frame_addr
      if(cur->swaped==1)
      {
        int i;
        for(i=0;i<8;i++)
        { //printf("READ_BLOCK\n"); 
          block_read(swap_disk,cur->sec_num+i,kpage+BLOCK_SECTOR_SIZE*i);
          bitmap_flip(swap_disk_bitmap,cur->sec_num+i);
        }        
        cur->swaped=0;
      //  lock_release(&file_sys_lock);
      }else{
      file_seek(cur->Ref_file,cur->ofs);
      if (kpage == NULL)
        return false;
      /* Load this page. */
      if (file_read (cur->Ref_file, kpage, cur->read_bytes) != (int) cur->read_bytes)
        {
          palloc_free_page (kpage);
          return false; 
        }
      memset (kpage + cur->read_bytes, 0, cur->zero_bytes);
 //     lock_release(&file_sys_lock);
      }      /* Add the page to the process's address space. */
      if (!install_page (cur->addr, kpage, cur->writable)) 
      {
        palloc_free_page (kpage);
        return false; 
      }  
    lock_release(&load_lock); 
   struct frame_entry* f=(struct frame_entry*)malloc(sizeof(struct frame_entry));
    f->frame_addr=kpage;
    f->writable=cur->writable;
    f->owner=thread_current();
    f->own_page=cur;
    list_push_back(&frame_table,&f->frame_elem);
  //  printf("VADDR : %x ALLOCATED WITH FRAME ADDR : %x\n",cur->addr, kpage);
    cur->is_loaded=1;
    cur->kaddr=f;
  //  printf("cur->kaddr %x\n",cur->kaddr->frame_addr);
      return true;
}
void expand_stack()
{
    if(list_size(&frame_table)>=786432)
    exit(-1);
    struct thread* cur=thread_current();
    while(!lock_try_acquire(&load_lock));
    uint8_t *kpage = palloc_get_page (PAL_USER|PAL_ZERO);
     if (!install_page ((uint8_t*)PHYS_BASE-(PGSIZE*(cur->stack_num++)), kpage, true))
     {
     palloc_free_page (kpage);
     }
      else
      {
        cur->esp=PHYS_BASE-(PGSIZE*(cur->stack_num));
       struct frame_entry* f=(struct frame_entry*)malloc(sizeof(struct frame_entry)); 
        f->frame_addr=kpage;                                                                
        f->writable=1;                                                        
        f->owner=cur;
        list_push_back(&frame_table,&f->frame_elem); 
          struct page_table_entry* p=(struct page_table_entry*)malloc(sizeof(struct page_table_entry));          
          p->addr=(uint8_t*)PHYS_BASE-(PGSIZE*(cur->stack_num++));
          p->writable=1;
          p->read_bytes=0;
          p->zero_bytes=PGSIZE;  
          p->stack_=1;
          p->swaped=0;
          p->is_loaded=1;
          hash_insert(&cur->supple_page,&p->h_elem);
          f->own_page=p;
      }
    lock_release(&load_lock);
}
