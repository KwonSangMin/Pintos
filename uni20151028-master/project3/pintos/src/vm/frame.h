#ifndef FRAME_H
#define FRAME_H
#include "../threads/thread.h"
#include "../lib/kernel/hash.h"
struct frame_entry{
  void* frame_addr;
  int writable;
  struct list_elem frame_elem;
  struct thread* owner;
  struct page_table_entry* own_page;
};
#endif
