#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <user/syscall.h>
#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "vm/frame.h"
#include "vm/page.h"

#define MAX_ARGS 3

static void syscall_handler (struct intr_frame *);
void get_arg (struct intr_frame *f, int *arg, int n);
struct sup_page_entry* check_valid_ptr (const void *vaddr, void* esp);
void check_valid_buffer (void* buffer, unsigned size, void* esp,
			 bool to_write);
void check_valid_string (const void* str, void* esp);
void check_write_permission (struct sup_page_entry *spte);
void unpin_ptr (void* vaddr);
void unpin_string (void* str);
void unpin_buffer (void* buffer, unsigned size);

void
syscall_init (void) 
{
  lock_init(&filesys_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  int arg[MAX_ARGS];
  check_valid_ptr((const void*) f->esp, f->esp);
  switch (* (int *) f->esp)
    {
    case SYS_HALT:
      {
	halt(); 
	break;
      }
    case SYS_EXIT:
      {
	get_arg(f, &arg[0], 1);
	exit(arg[0]);
	break;
      }
    case SYS_EXEC:
      {
	get_arg(f, &arg[0], 1);
	check_valid_string((const void *) arg[0], f->esp);
	f->eax = exec((const char *) arg[0]);
	unpin_string((void *) arg[0]);
	break;
      }
    case SYS_WAIT:
      {
	get_arg(f, &arg[0], 1);
	f->eax = wait(arg[0]);
	break;
      }
    case SYS_CREATE:
      {
	get_arg(f, &arg[0], 2);
	check_valid_string((const void *) arg[0], f->esp);
	f->eax = create((const char *)arg[0], (unsigned) arg[1]);
	unpin_string((void *) arg[0]);
	break;
      }
    case SYS_REMOVE:
      {
	get_arg(f, &arg[0], 1);
	check_valid_string((const void *) arg[0], f->esp);
	f->eax = remove((const char *) arg[0]);
	break;
      }
    case SYS_OPEN:
      {
	get_arg(f, &arg[0], 1);
	check_valid_string((const void *) arg[0], f->esp);
	f->eax = open((const char *) arg[0]);
	unpin_string((void *) arg[0]);
	break; 		
      }
    case SYS_FILESIZE:
      {
	get_arg(f, &arg[0], 1);
	f->eax = filesize(arg[0]);
	break;
      }
    case SYS_READ:
      {
	get_arg(f, &arg[0], 3);
	check_valid_buffer((void *) arg[1], (unsigned) arg[2], f->esp,
			   true);
	f->eax = read(arg[0], (void *) arg[1], (unsigned) arg[2]);
	unpin_buffer((void *) arg[1], (unsigned) arg[2]);
	break;
      }
    case SYS_WRITE:
      { 
	get_arg(f, &arg[0], 3);
	check_valid_buffer((void *) arg[1], (unsigned) arg[2], f->esp,
			   false);
	f->eax = write(arg[0], (const void *) arg[1],
		       (unsigned) arg[2]);
	unpin_buffer((void *) arg[1], (unsigned) arg[2]);
	break;
      }
    case SYS_SEEK:
      {
	get_arg(f, &arg[0], 2);
	seek(arg[0], (unsigned) arg[1]);
	break;
      } 
    case SYS_TELL:
      { 
	get_arg(f, &arg[0], 1);
	f->eax = tell(arg[0]);
	break;
      }
    case SYS_CLOSE:
      { 
	get_arg(f, &arg[0], 1);
	close(arg[0]);
	break;
      }
    case SYS_MMAP:
      {
	get_arg(f, &arg[0], 2);
	f->eax = mmap(arg[0], (void *) arg[1]);
	break;
      }
    case SYS_MUNMAP:
      {
	get_arg(f, &arg[0], 1);
	munmap(arg[0]);
	break;
      }
    }
  unpin_ptr(f->esp);
}

int mmap (int fd, void *addr)
{
  struct file *old_file = process_get_file(fd);
  if (!old_file || !is_user_vaddr(addr) || addr < USER_VADDR_BOTTOM ||
      ((uint32_t) addr % PGSIZE) != 0)
    {
      return ERROR;
    }
  struct file *file = file_reopen(old_file);
  if (!file || file_length(old_file) == 0)
    {
      return ERROR;
    }
  thread_current()->mapid++;
  int32_t ofs = 0;
  uint32_t read_bytes = file_length(file);
  while (read_bytes > 0)
    {
      uint32_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      uint32_t page_zero_bytes = PGSIZE - page_read_bytes;
      if (!add_mmap_to_page_table(file, ofs,
				  addr, page_read_bytes, page_zero_bytes))
	{
	  munmap(thread_current()->mapid);
	  return ERROR;
	}
      read_bytes -= page_read_bytes;
      ofs += page_read_bytes;
      addr += PGSIZE;
  }
  return thread_current()->mapid;
}

void munmap (int mapping)
{
  process_remove_mmap(mapping);
}

void halt (void)
{
  shutdown_power_off();
}

void exit (int status)
{
  struct thread *cur = thread_current();
  if (thread_alive(cur->parent) && cur->cp)
    {
      cur->cp->status = status;
    }
  printf ("%s: exit(%d)\n", cur->name, status);
  thread_exit();
}

pid_t exec (const char *cmd_line)
{
  pid_t pid = process_execute(cmd_line);
  struct child_process* cp = get_child_process(pid);
  if (!cp)
    {
      return ERROR;
    }
  if (cp->load == NOT_LOADED)
    {
      sema_down(&cp->load_sema);
    }
  if (cp->load == LOAD_FAIL)
    {
      remove_child_process(cp);
      return ERROR;
    }
  return pid;
}

int wait (pid_t pid)
{
  return process_wait(pid);
}

bool create (const char *file, unsigned initial_size)
{
  lock_acquire(&filesys_lock);
  bool success = filesys_create(file, initial_size);
  lock_release(&filesys_lock);
  return success;
}

bool remove (const char *file)
{
  lock_acquire(&filesys_lock);
  bool success = filesys_remove(file);
  lock_release(&filesys_lock);
  return success;
}

int open (const char *file)
{
  lock_acquire(&filesys_lock);
  struct file *f = filesys_open(file);
  if (!f)
    {
      lock_release(&filesys_lock);
      return ERROR;
    }
  int fd = process_add_file(f);
  lock_release(&filesys_lock);
  return fd;
}

int filesize (int fd)
{
  lock_acquire(&filesys_lock);
  struct file *f = process_get_file(fd);
  if (!f)
    {
      lock_release(&filesys_lock);
      return ERROR;
    }
  int size = file_length(f);
  lock_release(&filesys_lock);
  return size;
}

int read (int fd, void *buffer, unsigned size)
{
  if (fd == STDIN_FILENO)
    {
      unsigned i;
      uint8_t* local_buffer = (uint8_t *) buffer;
      for (i = 0; i < size; i++)
	{
	  local_buffer[i] = input_getc();
	}
      return size;
    }
  lock_acquire(&filesys_lock);
  struct file *f = process_get_file(fd);
  if (!f)
    {
      lock_release(&filesys_lock);
      return ERROR;
    }
  int bytes = file_read(f, buffer, size);
  lock_release(&filesys_lock);
  return bytes;
}

int write (int fd, const void *buffer, unsigned size)
{
  if (fd == STDOUT_FILENO)
    {
      putbuf(buffer, size);
      return size;
    }
  lock_acquire(&filesys_lock);
  struct file *f = process_get_file(fd);
  if (!f)
    {
      lock_release(&filesys_lock);
      return ERROR;
    }
  int bytes = file_write(f, buffer, size);
  lock_release(&filesys_lock);
  return bytes;
}

void seek (int fd, unsigned position)
{
  lock_acquire(&filesys_lock);
  struct file *f = process_get_file(fd);
  if (!f)
    {
      lock_release(&filesys_lock);
      return;
    }
  file_seek(f, position);
  lock_release(&filesys_lock);
}

unsigned tell (int fd)
{
  lock_acquire(&filesys_lock);
  struct file *f = process_get_file(fd);
  if (!f)
    {
      lock_release(&filesys_lock);
      return ERROR;
    }
  off_t offset = file_tell(f);
  lock_release(&filesys_lock);
  return offset;
}

void close (int fd)
{
  lock_acquire(&filesys_lock);
  process_close_file(fd);
  lock_release(&filesys_lock);
}

void check_write_permission (struct sup_page_entry *spte)
{
  if (!spte->writable)
    {
      exit(ERROR);
    }
}

struct sup_page_entry* check_valid_ptr(const void *vaddr, void* esp)
{
  if (!is_user_vaddr(vaddr) || vaddr < USER_VADDR_BOTTOM)
    {
      exit(ERROR);
    }
  bool load = false;
  struct sup_page_entry *spte = get_spte((void *) vaddr);
  if (spte)
    {
      load_page(spte);
      load = spte->is_loaded;
    }
  else if (vaddr >= esp - STACK_HEURISTIC)
    {
      load = grow_stack((void *) vaddr);
    }
  if (!load)
    {
      exit(ERROR);
    }
  return spte;
}

struct child_process* add_child_process (int pid)
{
  struct child_process* cp = malloc(sizeof(struct child_process));
  if (!cp)
    {
      return NULL;
    }
  cp->pid = pid;
  cp->load = NOT_LOADED;
  cp->wait = false;
  cp->exit = false;
  sema_init(&cp->load_sema, 0);
  sema_init(&cp->exit_sema, 0);
  list_push_back(&thread_current()->child_list,
		 &cp->elem);
  return cp;
}

struct child_process* get_child_process (int pid)
{
  struct thread *t = thread_current();
  struct list_elem *e;

  for (e = list_begin (&t->child_list); e != list_end (&t->child_list);
       e = list_next (e))
        {
          struct child_process *cp = list_entry (e, struct child_process, elem);
          if (pid == cp->pid)
	    {
	      return cp;
	    }
        }
  return NULL;
}

void remove_child_process (struct child_process *cp)
{
  list_remove(&cp->elem);
  free(cp);
}

void remove_child_processes (void)
{
  struct thread *t = thread_current();
  struct list_elem *next, *e = list_begin(&t->child_list);

  while (e != list_end (&t->child_list))
    {
      next = list_next(e);
      struct child_process *cp = list_entry (e, struct child_process,
					     elem);
      list_remove(&cp->elem);
      free(cp);
      e = next;
    }
}

void get_arg (struct intr_frame *f, int *arg, int n)
{
  int i;
  int *ptr;
  for (i = 0; i < n; i++)
    {
      ptr = (int *) f->esp + i + 1;
      check_valid_ptr((const void *) ptr, f->esp);
      arg[i] = *ptr;
    }
}

void check_valid_buffer (void* buffer, unsigned size, void* esp,
			 bool to_write)
{
  unsigned i;
  char* local_buffer = (char *) buffer;
  for (i = 0; i < size; i++)
    {
      struct sup_page_entry *spte = check_valid_ptr((const void*)
						    local_buffer, esp);
      if (spte && to_write)
	{
	  if (!spte->writable)
	    {
	      exit(ERROR);
	    }
	}
      local_buffer++;
    }
}

void check_valid_string (const void* str, void* esp)
{
  check_valid_ptr(str, esp);
  while (* (char *) str != 0)
    {
      str = (char *) str + 1;
      check_valid_ptr(str, esp);
    }
}

void unpin_ptr (void* vaddr)
{
  struct sup_page_entry *spte = get_spte(vaddr);
  if (spte)
    {
      spte->pinned = false;
    }
}

void unpin_string (void* str)
{
  unpin_ptr(str);
  while (* (char *) str != 0)
    {
      str = (char *) str + 1;
      unpin_ptr(str);
    }
}

void unpin_buffer (void* buffer, unsigned size)
{
  unsigned i;
  char* local_buffer = (char *) buffer;
  for (i = 0; i < size; i++)
    {
      unpin_ptr(local_buffer);
      local_buffer++;
    }
}
