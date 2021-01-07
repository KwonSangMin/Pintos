#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
typedef int pid_t;
void syscall_init (void);
struct file* find_fild(int fd);
int filesize(int);
void halt(void);
void exit(int );
int create(const char *, unsigned);
void close(int );
int open(const char *);
int write(int, const void*, unsigned);
int read (int, void*, unsigned);
int remove(const char*);
pid_t exec (const char*);
int wait (pid_t);
void seek(int,unsigned);
unsigned tell(int);
#endif /* userprog/syscall.h */
