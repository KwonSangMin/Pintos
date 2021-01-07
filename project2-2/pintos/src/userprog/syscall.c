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
//    printf("WRITE\n");
    if(!is_user_vaddr(f->esp+28)) exit(-1);
    f->eax= write(*(int*)(f->esp+20),(void*)*(int32_t*)(f->esp+24),*(unsigned*)(f->esp+28)); 
    break; 
    case SYS_WAIT:
    if(!is_user_vaddr(f->esp+4))exit(-1);
    f->eax=wait(*(int*)(f->esp+4));
    break; 
    case SYS_READ:
//    printf("READ\n");
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
//    printf("SEEK\n");
   if(!is_user_vaddr(f->esp+20))exit(-1);
    seek(*(int*)(f->esp+16),*(unsigned*)(f->esp+20));
    break; 
  }

 // thread_exit ();
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
//  printf("OPEN : %s",file);
  if(*file==NULL)
    {return -1;} 
  struct thread* cu=thread_current();
  while(!lock_try_acquire(&file_sys_lock));
    (cu->opening_num)+=1;
    cu->open_file[cu->opening_num]= filesys_open(file);
  lock_release(&file_sys_lock);
  if(cu->open_file[cu->opening_num]!=NULL)//can find file
  {// file_deny_write(cu->open_file[cu->opening_num]);
  return cu->opening_num;}//return fd 
  else{cu->opening_num--;
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
 while(!(lock_try_acquire(&file_sys_lock)));
 int x= filesys_remove(file);
  lock_release(&file_sys_lock);
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
