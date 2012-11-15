#ifndef VM_SWAP_H
#define VM_SWAP_H

#include "devices/block.h"
#include "threads/synch.h"
#include <bitmap.h>

#define SWAP_FREE 0
#define SWAP_IN_USE 1

#define SECTORS_PER_PAGE (PGSIZE / SECTOR_SIZE)

struct lock swap_lock;

struct block *swap_block;

struct bitmap swap_map;

#endif /* vm/swap.h */
