#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <stdbool.h>
#include <stdint.h>
#include <list.h>

struct lock frame_table_lock;

struct list frame_table;

struct frame_entry {
  void *frame;
  tid_t tid;
  uint32_t *pte;
  struct list_elem elem;
};

void frame_table_init (void);
void* frame_alloc (enum palloc_flags flags);
void frame_free (void *frame);
void frame_add_to_table (void *frame);
bool frame_evict (void *frame);

#endif /* vm/frame.h */
