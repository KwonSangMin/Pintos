#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/shutdown.h"
#include "../filesys/filesys.h"
#include "process.h"
#include "../threads/vaddr.h"
#include "string.h"
static void syscall_handler (struct intr_frame *);
extern struct lock file_sys_lock;
void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}
static void
syscall_handler (struct intr_frame *f UNUSED) 
{ 
//  hex_dump(f->esp,f->esp,100,1);
   if(!is_user_vaddr(f->esp)) exit(-1);

    thread_current()->k_esp=f->esp;
  //esp->syscall_number
  //halt() exit() create() open() close()
  //f->esp below PHYS_BASE, pointer arg also below PHYS_BASE, isnt point unmapped memory space, (NULL POINTER?)
  //normally prefferd just check below PHYS_BASE
  ////f->esp < PHYS_BASE-> return 1 
 // hex_dump(f->esp,f->esp,1000,1); 
 switch(*(uint8_t*)(f->esp))
  {
    case SYS_REMOVE :
    if(!is_user_vaddr(f->esp+4))exit(-1);
    f->eax=remove((char*)*(int*)(f->esp+4));
    break;
    case SYS_CREATE :
    if(!is_user_vaddr(f->esp+20)) exit(-1);
   // printf("%s , %i \n",(char*)*(int*)(f->esp+16),*(int*)(f->esp+20));
    f->eax= create((char*)*(int*)(f->esp+16),*(int*)(f->esp+20));
    break;
    case SYS_OPEN :
//    printf("OPEN\n");
    if(!is_user_vaddr(f->esp+4)) exit(-1);
    f->eax= open((char*)*(int32_t*)(f->esp+4));//const char *file
//    printf("OPENFINISH\n");
    break;
    case SYS_CLOSE :
    if(!is_user_vaddr(f->esp+4)) exit(-1);
    close(*(int*)f->esp+4);//int fd
    break;
    case SYS_HALT :
    halt();//void
    break;
    case SYS_EXIT :
    if(!is_user_vaddr(f->esp+4)) exit(-1);
    exit(*(int*)(f->esp+4));//int status
    break;
    case SYS_WRITE:
   // printf("WRITE\n");
    if(!is_user_vaddr(f->esp+28)) exit(-1);
    f->eax= write(*(int*)(f->esp+20),(void*)*(int32_t*)(f->esp+24),*(unsigned*)(f->esp+28)); 
    break; 
    case SYS_WAIT:
    if(!is_user_vaddr(f->esp+4))exit(-1);
    f->eax=wait(*(int*)(f->esp+4));
    break; 
    case SYS_READ:
   // printf("READ\n");
    if(!is_user_vaddr(f->esp+28))exit(-1);
    f->eax=read(*(int*)(f->esp+20),(void*)*(int32_t*)(f->esp+24),*(unsigned*)(f->esp+28));
    break;
    case SYS_EXEC:
    if(!is_user_vaddr(f->esp+4))exit(-1);
    f->eax=exec((char*)*(int32_t*)(f->esp+4));
    break;
    case SYS_FILESIZE:
    if(!is_user_vaddr(f->esp+4))exit(-1);
    f->eax=filesize(*(int*)(f->esp+4));
    break;
    case SYS_TELL:
    if(!is_user_vaddr(f->esp+4))exit(-1);
    f->eax=tell(*(int*)(f->esp+4));
    break;  
  case SYS_SEEK: 
 //   printf("SEEK\n");
   if(!is_user_vaddr(f->esp+20))exit(-1);
    seek(*(int*)(f->esp+16),*(unsigned*)(f->esp+20));
    break;
    case SYS_MMAP:
    if(!is_user_vaddr(f->esp+20))exit(-1);
    f->eax=mmap(*(int*)(f->esp+16),(void*)*(int32_t*)(f->esp+20));
    //printf("SYS_MMAP FINISH\n"); 
    break;
    case SYS_MUNMAP: 
  if(!is_user_vaddr(f->esp+20))exit(-1);
    munmap(*(int*)(f->esp+4));
    break; 
  }
}
void munmap(mapid_t mapid)
{
  struct thread* cur=thread_current();
  if(!list_empty(&(cur->memory_map_list)))
  {
    struct memory_map_entry* x=list_entry(list_prev(list_end(&cur->memory_map_list)),struct memory_map_entry, mm_elem);
    struct memory_map_entry* t;
    for(;t!=x;)
    {
      t=list_entry(list_pop_front(&(cur->memory_map_list)),struct memory_map_entry, mm_elem);
      if(t->mapid==mapid)
      {
        while(!list_empty(&t->supple_page_list))
        {
          struct page_table_entry* pg=list_entry(list_pop_front(&t->supple_page_list),struct page_table_entry, elem);
                  if(pagedir_is_dirty(cur->pagedir,pg->addr))
          {
                    file_write_at(pg->Ref_file,pg->addr,pg->read_bytes,pg->ofs); 
          }
          palloc_free_page(pagedir_get_page(cur->pagedir,pg->addr));
          pagedir_clear_page(cur->pagedir,pg->addr);
          hash_delete(&cur->supple_page,&pg->h_elem);
        }
      }
      else
      list_push_front(&(cur->memory_map_list),&t->mm_elem);
    }
  } 
}
mapid_t mmap(int fd, void* addr)
{
  int x = (uint8_t*)addr;
  x%=0x1000;
  if(fd==0||fd==1||addr==0||x!=0)
  {
//    printf("FD \n");
    return -1;
  }
  struct thread* cur=thread_current();
  if(addr>=cur->esp)
  {// printf("K_ESP\n");
    return -1;
    } 
  struct memory_map_entry* mm=(struct memory_map_entry*)malloc(sizeof(struct memory_map_entry));
  mm->mapid=fd;
  struct file* file=file_reopen(find_fild(fd));
  mm->file=file;
  list_init(&mm->supple_page_list);
  if(filesize(fd)==0||page_lookup(addr)!=NULL)
  {
   // printf("fd\n");
    return -1;
  }
  uint32_t read_bytes = filesize(fd);
 // printf("read_bytes : %d\n",read_bytes);
  uint8_t* upage=(uint8_t*)addr;
//  printf("upage : %x\n",upage);
  uint32_t zero_bytes=PGSIZE-(read_bytes%PGSIZE);
 // printf("zero_bytes : %d\n",zero_bytes);
  int ofs =0; 
  while(read_bytes>0||zero_bytes>0)
  {
    struct page_table_entry* p=(struct page_table_entry*)malloc(sizeof(struct page_table_entry));
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;
      p->Ref_file=file;
      p->read_bytes=page_read_bytes;
      p->zero_bytes=page_zero_bytes;
      p->addr=upage;
      p->ofs=ofs;      
      p->writable=1;
      p->mapid=fd; 
      p->is_loaded=0; 
      p->swaped=0;
      hash_insert(&cur->supple_page,&p->h_elem);
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
      ofs +=PGSIZE;
      list_push_front(&(mm->supple_page_list),&p->elem);      
//      printf("Store : %x, at VADDR : %x\n",p->Ref_file,p->addr);
  } 
    list_push_front(&cur->memory_map_list,&mm->mm_elem);
  //printf("finish mmap %d\n",fd);
  return fd;
}
int filesize(int fd)
{
  return file_length(find_fild(fd)); 
}
void halt(void)
{
  shutdown_power_off();  
}
void exit(int status)
{
  //  printf("EXIT BY CHILD AND CALL PARENT_PTR : %i",thread_current()->parent_ptr);
    struct thread* cur=thread_current();
   printf("%s: exit(%i)\n",thread_current()->name, status);
/*  for(;cur->opening_num>1;cur->opening_num--)
  {
    close(cur->opening_num);
  }*/
 //  sema_up(&cur->wait_child);
  cur->exit_state=status;
   thread_exit();//terminate user program
}
int create(const char* file, unsigned initial_size) 
{
 if(*file==NULL)
  {
    exit(-1);
  }
  else if(strlen(file)>14||strlen(file)<=0)
  { 
    return 0;
  }
  while(!lock_try_acquire(&file_sys_lock));
  int i = filesys_create(file,initial_size); 
  lock_release(&file_sys_lock);
  return i;
} 
int open(const char *file)//file open -> the file describtor number return it is unique
{
 //printf("OPEN : %s",file);
  struct thread* cu=thread_current();
  if(*file==NULL)
    { 
      return -1;
    }  
  while(!lock_try_acquire(&file_sys_lock));
    (cu->opening_num)+=1;
    cu->open_file[cu->opening_num]= filesys_open(file);
  lock_release(&file_sys_lock);
  if(cu->open_file[cu->opening_num]!=NULL)//can find file
  {// file_deny_write(cu->open_file[cu->opening_num]);
    return cu->opening_num;}//return fd 
    else{
    cu->opening_num--;
    return -1;
  }
}
void close(int fd)
{
// while(!lock_try_acquire(&file_sys_lock));
 file_close(find_fild(fd));
//lock_release(&file_sys_lock);
}
struct file* find_fild(int fd)
{
  struct thread* cur=thread_current();
   if(cur->opening_num<fd)
  {
    return NULL;}
  else if(cur->opening_num>=fd)
  {
        return cur->open_file[fd];
  }
}
int write(int fd,const void* buffer, unsigned size)
{
//  while(!lock_try_acquire(&file_sys_lock));
    if (fd == 1) {
    while(!lock_try_acquire(&file_sys_lock));  
  putbuf(buffer, size);
    lock_release(&file_sys_lock);
    return size;
  }
  else if(fd>=2)
  {
    struct file* Target_file=find_fild(fd);
    if(is_deny(Target_file)==1)return 0;
    if(!is_user_vaddr(buffer))exit(-1);
   while(!lock_try_acquire(&file_sys_lock));
    int write_byte=file_write(Target_file,buffer,size); 
    lock_release(&file_sys_lock);
    return write_byte;
  }
//  lock_release(&file_sys_lock);
  return -1;  
}
pid_t exec(const char* cmd_line)
{
  pid_t Child= process_execute(cmd_line);   
  if(thread_current()->load_state==-1)
  {
    thread_current()->load_state=0;
    return -1;
  }
  return Child;
   
}
int read(int fd, void* buffer, unsigned size)
{
  if(!is_user_vaddr(buffer))exit(-1);
  while(!lock_try_acquire(&file_sys_lock));
  int read_byte;
  if(fd==0)
  {
    buffer=input_getc();
   lock_release(&file_sys_lock);
    return size;
  }
  else
  {
    if(find_fild(fd)==NULL)
    {
exit(-1);} 
  read_byte= file_read(find_fild(fd),buffer,size);
    lock_release(&file_sys_lock);   
   return read_byte;
  }
}
int remove(const char* file)
{
//  printf("file : %s",file);
 while(!(lock_try_acquire(&file_sys_lock)));
 int x= filesys_remove(file);
  lock_release(&file_sys_lock);
 // printf("%d",x);
  return x;
}
int wait(pid_t pid)
{
 return process_wait(pid);
}
void seek(int fd, unsigned position)
{
  file_seek(find_fild(fd),position); 
}
unsigned tell(int fd)
{
  return file_tell(find_fild(fd));

}
