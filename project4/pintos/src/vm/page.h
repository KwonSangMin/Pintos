#ifndef PAGE_H
#define PAGE_H
#include "../filesys/file.h"
#include "../filesys/filesys.h"
#include "../lib/kernel/hash.h"
#include "../threads/thread.h"
#include "../threads/vaddr.h"
#include "frame.h"
struct page_table_entry{
  int mapid;
  struct file* Ref_file;
  off_t ofs;  
  uint32_t read_bytes;
  uint32_t zero_bytes;
  bool writable;
  bool is_loaded;
  struct hash_elem h_elem;
  struct list_elem elem;
  void* addr;
  struct frame_entry* kaddr;
  bool stack_;
  bool swaped;
  int sec_num;
};
unsigned page_hash(const struct hash_elem*, void*);
bool page_less(const struct hash_elem* , const struct hash_elem*, void*);
struct page_table_entry* page_lookup(const void*);
#endif
