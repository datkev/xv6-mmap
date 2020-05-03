#include "param.h"
#include "types.h"
#include "defs.h"
#include "x86.h"
#include "memlayout.h"
#include "mmu.h"
#include "proc.h"
#include "mmap.h"
#include "mman.h"
#include "fs.h"
#include "spinlock.h"
#include "sleeplock.h"
#include "file.h"


// Create a new maplist entry
// Return pointer to entry
struct maplist * ml_new_entry(void *addr, int length, int prot, int flags, int fd, int offset) {
  struct maplist *p;

  // failed to allocate memory for pointer to entry
  if ((p = kmalloc(sizeof(*p))) == NULL)
    return NULL;
  
  p->next = NULL;
  p->addr = addr;
  p->len = length;
  p->prot = prot;
  p->flags = flags;
  p->fd = fd;
  p->offset = offset;
  p->allocated = 0;

  return p;
}


// Add a maplist entry to maplist 
int ml_add(void *addr, int length, int prot, int flags, int fd, int offset) {
  struct maplist *p = myproc()->ml;

  // Create new entry
  struct maplist *new_entry = ml_new_entry(addr, length, prot, flags, fd, offset);
  if (new_entry == NULL) {
    return -1;
  }

  // Set new entry as head
  if (p == NULL) {
    myproc()->ml = new_entry;
    return 0;
  }

  // Insert entry in increasing order of address
  while (p->next && p->next->addr < addr) {
    p = p->next;
  }
  struct maplist *n = p->next;
  p->next = new_entry;
  new_entry->next = n;
  return 0;
}


// Gets the next available page-aligned region starting from address, ending at addr+length
// Returns the new starting address
int ml_get_next(void *addr, int length) {
  uint start = PGROUNDUP((uint)addr);
  struct maplist *p = myproc()->ml;
  while (start < KERNBASE) {
    // look for entry with end address >= new region's start
    while (p && PGROUNDUP((uint)(p->addr+p->len)) <= start)
      p = p->next;
    // check that next entry's start address does not conflict with end address of new region
    if (p == NULL || start+length <= (uint)p->addr)
      break;
    start += PGSIZE;
  }

  if (start >= KERNBASE)
    return -1;

  return start;
}


// Remove a maplist entry from maplist
// Return pointer to maplist entry
struct maplist * ml_remove(void *addr, int length){
  struct maplist *prevp = NULL;
  struct maplist *p = myproc()->ml;

  // Find entry with matching address and length
  while (p && p->addr != addr && p->len != length) {
    prevp = p;
    p = p->next;
  }

  // Entry not found
  if (p == NULL) {
    return NULL;
  }
  
  if (prevp == NULL) { // Entry is head of the list
    myproc()->ml = p->next;
    return p;
  } else { // Entry not head of list
    prevp->next = p->next;
    return p;
  }
}


// Find an entry with matching start address in the maplist
struct maplist * ml_find(void *addr) {
  struct maplist *p = myproc()->ml;

  while (p && p->addr != addr)
    p = p->next;
  
  return p;
}


// Print mmap attributes
void ml_print_entry(struct maplist *p) {
  cprintf("addr: 0x%x, len: %d, prot: %d, flags: %d, offset: %d, fd: 0x%x, allocated: %d\n", 
          p->addr, p->len, p->prot, p->flags, p->offset, p->fd, p->allocated);
}


// Print current process' map list
void ml_print() {
  int i = 0;
  struct maplist *p = myproc()->ml;
  cprintf("===Maplist print:===\n");
  while (p != NULL) {
    cprintf("Maplist entry %d:  ", i++);
    ml_print_entry(p);
    p = p->next;
  }
  cprintf("===End maplist===\n");
}


// Create new mapping in process address space.
// If addr is NULL, then the kernel chooses address. Else kernel may or may not take hint
// to place the new region at the nearest page-aligned address. If another mapping already
// exists there, then the kernel will pick another address. New regions will always begin
// at page-aligned addresses.
//
// Returns starting address of the newly mapped
void * mmap(void *addr, int length, int prot, int flags, int fd, int offset) {
  void *start = (void *)(MMAPBASE+(uint)addr);
  struct file *fdup = NULL;

  // get next available address greater than or equal to start
  start = (void*)ml_get_next(start,length);

  // check memory region
  if (flags != -1) {
    if (((flags & MAP_ANONYMOUS) == MAP_ANONYMOUS) && (uint)fd != -1){
      return (void*)-1;
    } else if ((flags & MAP_FILE) == MAP_FILE) {
      // check if fd is within valid range
      if(fd < 0 || fd >= NOFILE || (myproc()->ofile[fd]) == 0)
        return (void*)-1;

      // check r/w
      struct file *f = myproc()->ofile[fd];
      if (f->readable == 0 || f->writable == 0)
        return (void*)-1;
      
      fdup = filedup(f);
      fileseek(fdup, offset);
    }
  }

  // track mmap'ed region in maplist
  if (ml_add(start, length, prot, flags, (int)fdup, offset) < 0)
    return (void*)-1;
  
  // ml_print();
  
  return start;
}


// Scan map list to find mapped page matching addr and length arguments
// Clear memory region to be unmapped
// Handle file-backed regions by closing the associated fd
// Returns 0 if successful, -1 otherwise
int munmap(void *addr, uint length) {
  struct proc *curproc = myproc();
  struct maplist *p = NULL;

  // Remove element from map list
  if ((p = ml_remove(addr, length)) == NULL)
    return -1;

  if (p->fd > 0) 
    fileclose((struct file *)p->fd);
  
  // Only deallocate if previously allocated
  if (p->allocated == 1) {
    // Clear memory
    memset(addr,0,length);
    
    // Unmap memory region
    if (deallocuvm(curproc->pgdir, (uint)addr+length, (uint)addr) == 0)
      return -1;
  }

  // Free map list element
  kmfree(p);

  return 0;
}


// Write chages to memory region back to file
// Only writes to pages that have been allocated
// Returns 0 if successful, else -1
int msync(void* start_addr, int length) {
  uint a = (uint)start_addr;
  uint end = (uint)start_addr + length;
  struct maplist *ml_entry = NULL;
  pde_t *pgdir = myproc()->pgdir;

  // get maplist entry
  if ((ml_entry = ml_find(start_addr)) == NULL)
    return -1;

  // get fd
  struct file *f = (struct file*)ml_entry->fd;
  if (f == NULL)
    return -1;  
  
  // reset offset before msync
  fileseek(f, 0);

  // write pages if dirty bit is set
  // filewrite writes min(PGSIZE, EOF-a) bytes
  for (;a < end; a+=PGSIZE) {
    pde_t *pte = NULL;
    if ((pte = walkpgdir(pgdir, (void *)a, 0)) != NULL && CHECKBIT((uint)*pte,PTE_D) > 0) {
      // cprintf("entering filewrite, pte: 0x%x, pte_d: %d\n", pte, CHECKBIT((uint)*pte,PTE_D));
      filewrite(f, (char *)a, PGSIZE);
    }
  }

  return 0;
}



