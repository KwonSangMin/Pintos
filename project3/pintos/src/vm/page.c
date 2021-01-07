#include "page.h"
unsigned page_hash(const struct hash_elem* p_, void* aux)
{
  const struct page_table_entry* p=hash_entry(p_,struct page_table_entry, h_elem);
  return hash_bytes(&p->addr, sizeof p->addr);
}
bool page_less(const struct hash_elem *a_, const struct hash_elem *b_, void* aux)
{
  const struct page_table_entry *a=hash_entry(a_,struct page_table_entry,h_elem);
  const struct page_table_entry *b=hash_entry(b_,struct page_table_entry,h_elem);
  return a->addr<b->addr;
}
struct page_table_entry* page_lookup(const void *address)
{
  struct thread* c=thread_current(); 
  struct page_table_entry p;
  p.addr=pg_round_down(address);
  struct hash_elem *e=hash_find(&(c->supple_page),&(p.h_elem));
  if(e==NULL){
  return NULL;
}
  struct page_table_entry* x=hash_entry(e,struct page_table_entry,h_elem);
  return x;
}
