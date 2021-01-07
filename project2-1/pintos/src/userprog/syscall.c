#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/shutdown.h"
#include "../filesys/filesys.h"
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
  //esp->syscall_number
  //halt() exit() create() open() close()
  //f->esp below PHYS_BASE, pointer arg also below PHYS_BASE, isnt point unmapped memory space, (NULL POINTER?)
  //normally prefferd just check below PHYS_BASE
  ////f->esp < PHYS_BASE-> return 1 
 // hex_dump(f->esp,f->esp,1000,1); 
 switch(*(uint8_t*)(f->esp))
  {
    case SYS_CREATE :
    if(!is_user_vaddr(f->esp+20)) exit(-1);
   // printf("%s , %i \n",(char*)*(int*)(f->esp+16),*(int*)(f->esp+20));
    f->eax= create((char*)*(int*)(f->esp+16),*(int*)(f->esp+20));
    break;
    case SYS_OPEN :
    if(!is_user_vaddr(f->esp+4)) exit(-1);
    f->eax= open((char*)*(int*)(f->esp+4));//const char *file
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
    if(!is_user_vaddr(f->esp+28)) exit(-1);
    f->eax= write(*(int*)(f->esp+20),(void*)*(int32_t*)(f->esp+24),*(unsigned*)(f->esp+28)); 
    break; 
    case SYS_WAIT:

    break; 
    default : 
    printf("DEFAULT : %i",*(int*)f->esp);
    break;
  }

 // thread_exit ();
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
  for(;cur->opening_num>1;cur->opening_num--)
  {
    close(cur->opening_num);
  }
    
   sema_up(&cur->wait_child);
  cur->exit_state=status;
  if(cur->parent_ptr!=NULL) 
   list_remove(&cur->chelem);
   thread_exit();//terminate user program
}
int create(const char* file, unsigned initial_size) 
{
   
 // while(file_sys_use==1){}
 // file_sys_use=1; 
// while(!lock_try_acquire(&file_sys_lock));
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
 // file_sys_use=0;
 // return i; 
 // intr_set_level(old_level);
}
int open(const char *file)//file open -> the file describtor number return it is unique
{
 // while(lock_try_acquire(&file_sys_lock));
  if(*file==NULL)
    {return -1;} 
  struct thread* cu=thread_current();
//  printf("OPEN ---->>>> %s\n",file); 
 // struct thread* cur = thread_current();
// enum intr_level old_level=intr_disable();
 while(!lock_try_acquire(&file_sys_lock));
    cu->opening_num++;
    cu->open_file[cu->opening_num]= filesys_open(file);
  // intr_set_level(old_level);
//  printf("opening_num : %i\n",cur->opening_num)
  lock_release(&file_sys_lock);
  if(cu->open_file[cu->opening_num]!=NULL)//cant find file
  { return cu->opening_num; }
  else{cu->opening_num--;
  return -1;
  }
}
void close(int fd)
{
  while(!lock_try_acquire(&file_sys_lock));
 file_close(find_fild(fd));
  lock_release(&file_sys_lock);
}
struct file* find_fild(int fd)
{
  struct thread* cur=thread_current();
   if(cur->opening_num<fd)
  {
    return NULL;}
  else if(cur->opening_num>=fd)
  {   struct thread* cur = thread_current();
      if(cur->open_file[fd]!=NULL)
      {
        return cur->open_file[fd];
      }
  }
}
int write(int fd,const void* buffer, unsigned size)
{
    if (fd == 1) {
    putbuf(buffer, size);
    return size;
  }
  else if(fd>=3)
  {
    return size;
  }
  return -1;  
}
