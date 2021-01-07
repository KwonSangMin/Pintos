#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
void syscall_init (void);
struct file* find_fild(int fd);
void halt(void);
void exit(int );
int create(const char *, unsigned);
void close(int );
int open(const char *);
int write(int, const void*, unsigned);
#endif /* userprog/syscall.h */
