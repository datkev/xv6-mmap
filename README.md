# xv6-mmap
mmap implementation on top of xv6

Steps to implementing a file-backed **mmap()**:
1. Add a memory allocator for the kernel via **kmalloc()** and **kmfree()**
2. Add a linked list to keep track of memory mappings from **mmap()**
3. Add anonymous **mmap()** (not file-backed)
4. Add file-backing capabilities to **mmap()**


## kmalloc()
In this section, we build a memory allocator for the kernel. We already have a user-space allocator, **umalloc()**, so we borrow much of the existing code from Kernighan and Ritchie’s **umalloc()** and make some modifications. Unlike memory allocated for user-space, memory allocated for the kernel is not freed upon termination of the process. This way, the kernel is safe to use the allocated memory without risk of losing data when a process is terminated.

Currently, the **morecore()** call within **umalloc()** allocates a minimum of 4096 units of size, sizeof(Header), by calling **sbrk()**. In **kmalloc()**, since we don’t want to grow user space by calling **sbrk()** (which calls **growproc()**), we call **kalloc()** directly to allocate a page of memory for the kernel.

This page will be added to a list of memory chunks, reserved for kernel use, to be distributed by our function **kmalloc()**. Maintaining a list of unallocated memory allows us to distribute from this list any time a call to **kmalloc()** is made without necessarily having to make a new call to **kalloc()**. As long as the call to **kmalloc()** requests for a size of memory equal to or less than the size of an existing unallocated chunk in our free list, we can reuse any suitably sized chunk from previous calls to **kalloc()**.

The structure of our free list remains the same as the **umalloc()** free list.

We assume that the call to **kmalloc()** is limited to 4096 bytes and add a panic if the request is greater than a page in length.

In **kmalloc.c**:
```C
void * kmalloc(uint nbytes){
  Header *p, *prevp;
  uint nunits;

  if (nbytes > 4096)
    panic("Request for more than 4096 bytes in kmalloc()");

  nunits = (nbytes + sizeof(Header) - 1)/sizeof(Header) + 1;    // align to header size, rounded up, add one for header
  if((prevp = freep) == 0){                                     // no free list yet, first call malloc
    base.s.ptr = freep = prevp = &base;                         // degenerate list
    base.s.size = 0;
  }
  for(p = prevp->s.ptr; ; prevp = p, p = p->s.ptr){             // for each chunk in free list..
    if(p->s.size >= nunits){                                    
      if(p->s.size == nunits)                                   // exactly right size
        prevp->s.ptr = p->s.ptr;
      else {
        p->s.size -= nunits;                                    // set p to tail end of chunk
        p += p->s.size;                                         // retain beginning of chunk in free list
        p->s.size = nunits;                                     
      }
      freep = prevp;                                            // free pointer now at prev
      return (void*)(p + 1);                                    // return free region after header
    }
    if(p == freep)                                              // full cycle
      if((p = kmorecore()) == 0)
        return 0;
  }
}
```


## kmorecore()

In **kmalloc()**, if we find that our free list does not contain a chunk of memory large enough for the current request, we call **kmorecore()**, a modified version of **morecore()** which calls **kalloc()** instead of **sbrk()** to allocate a page of memory for the kernel. Since **kalloc()** allocates 4096 bytes, we need adjust the size in the header to specify the number of header-sized units the chunk contains.

In **kmalloc.c**:
```C
static Header * kmorecore() {
  char *p;
  Header *hp;

  p = kalloc();                                                // allocate page of memory for kernel
  if (!p)
    return 0;

  hp = (Header*)p;
  hp->s.size = 4096/sizeof(Header);
  kmfree((void*)(hp + 1));
  return freep;
}
```

## kmfree()

The code for **kmfree()** does not change from the code for K&R’s free. In a nutshell, the **kmfree()** code assumes the free list is in increasing order of addresses within the kernel space. If the chunk to be freed is adjacent to a chunk in the list, it merges with the adjacent chunk. It is possible for the chunk to merge with two adjacent chunks in the list. If the chunk cannot be merged, then it is placed at the appropriate location within the list, maintaining the invariant of increasing addresses.


## Adding system calls

As usual, our system calls will need to modify the **usys.S**, **syscall.h**, and **syscall.c** files. We can fetch the system call arguments using wrappers defined in **sysproc.c**. Note that we can’t use **argptr** for **kmfree()** since **argptr** requires the address of the pointer argument be in user space. Since **kmalloc()** will be returning addresses in kernel space, calls to **kmfree()** will need to pass pointers with addresses in kernel space.

In **sysproc.c**:
```C
int sys_kmalloc(void) {
  int n;
  void *p;
  if(argint(0, &n) < 0)
    return -1;
  if ((int)(p = kmalloc((uint)n)) == 0)
    return -1;
  return (int)p;
}
```

```C
int sys_kmfree(void) {
  int a;
  if(argint(0, &a) < 0)
    return -1;
  kmfree((char *)a);
  return 0;
}
```

## maplist struct
In this section, we construct the data structure used to keep track of the memory mappings allocated by mmap. The data structure we use is a simple linked list that maintains an increasing order of addresses for the mapped pages provided in **mmap.h**.

In **mmap.h**:
```C
struct maplist {
  struct maplist *next;
  void *addr;
  int len;
  int flags;
  int offset;
  int fd;
};
```
Within the struct proc in **proc.h**, we’ll keep a reference to the head of the maplist.
```C
struct maplist *ml;
```
In **proc.c**, the **userinit()** function will initialize the head of the map list to 0.
```C
// Initialize maplist for mmap
p->ml = 0;
```
In addition, in **fork()**, child processes inherit the map list from parent processes.
```C
np->ml = curproc->ml;
```


## mmap()

Within **mmap.c**, the **mmap()** function uses **allocuvm()** to grow the process’ user space, taking the **addr**
argument as a hint for where to place the starting address for the new region. We define **MMAPBASE** to be `0x4000000`,
meaning all mmapped regions will be mapped beyond `0x4000000` (halfway to KERNBASE). In order
to take the user-supplied address as a “hint”, the function **ml_get_next()** finds the next available page-
aligned address using the user-supplied **addr** as an offset from **MMAPBASE**. If we cannot find an
address between **MMAPBASE** and **KERNBASE**, using **addr** as an offset, **mmap()** fails. Using
**memset()**, we clear the newly mapped region and add a new element to our map list based on the
attributes (arguments) of the region. If we don’t have enough space in the kernel to store the new list
element, we need to be sure to deallocate the allocated region.

```C
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
```

```C
void * mmap(void *addr, int length, int prot, int flags, int fd, int offset) {
  void *start = (void *)(MMAPBASE+(uint)addr);
  uint end;
  struct proc *curproc = myproc();
  
  // Return next free page-aligned address that can accommodate length
  start = (void*)ml_get_next(start,length);

  if ((uint)start < 0)
    return (void*)-1;
  if ((end = allocuvm(curproc->pgdir, (uint)start, (uint)start+length)) == 0)
    return (void*)-1;

  memset(start,0,length);

  // Track memory mapped region in maplist
  if (ml_add(start, length, flags, fd, offset) < 0) {
    deallocuvm(curproc->pgdir,end,(uint)start);
    return (void*)-1;
  }
  
  return start;
}
```

## maplist helpers

For each memory mapped region, we keep track of the starting address, length, region type, offset, and
hold a duplicate of the file descriptor. Any time a call to **mmap()** is made, we add a list element with this
metadata for the mapping. As mentioned before, elements are ordered in increasing order of mapped
page address, so we can perform a linear scan for insertion and deletion.

```C
// Create a new maplist entry
// Return pointer to entry
struct maplist * ml_new_entry(void *addr, int length, int flags, int fd, int offset) {
  struct maplist *p;

  // failed to allocate memory for pointer to entry
  if ((p = kmalloc(sizeof(*p))) == NULL)
    return NULL;
  
  p->next = NULL;
  p->addr = addr;
  p->len = length;
  p->flags = flags;
  p->fd = fd;
  p->offset = offset;

  return p;
}
```

```C
// Add a maplist entry to maplist 
int ml_add(void *addr, int length, int flags, int fd, int offset) {
  struct maplist *p = myproc()->ml;

  // Create new entry
  struct maplist *new_entry = ml_new_entry(addr, length, flags, fd, offset);
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
```

```C
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
```

## munmap()

When it comes time to unmap a mapped region, we can call **munmap()**, which will first search for a
mapped region in our map list matching the addr and length arguments. Assuming we find a matching
region, we then clear the region using **memset()**. Then, using **deallocuvm()**, we unmap the memory region
in page sized chunks. Finally, we need to free the list element tracking the mapped region using
**kmfree()**.

```C
int munmap(void *addr, uint length) {
  struct proc *curproc = myproc();
  struct maplist *p;

  // Remove element from map list
  if ((p = ml_remove(addr, length)) == NULL)
    return -1;

  // Clear memory
  memset(addr,0,length);
  // Unmap memory region
  if (deallocuvm(curproc->pgdir, (uint)addr+length, (uint)addr) == 0)
    return -1;

  // Free map list element
  kmfree(p);

  return 0;
}
```

## Adding more system calls

In order to add the system calls, will need to modify the **usys.S**, **syscall.h**, and **syscall.c** files. As
before, we can fetch the system call arguments using wrappers defined in **sysproc.c**.

```C
int sys_mmap(void) {
  int addr, len, prot, flags, fd, offset;
  if ((argint(0, &addr) < 0) ||
      (argint(1, &len) < 0) ||
      (argint(2, &prot) < 0) ||
      (argint(4, &flags) < 0) ||
      (argint(5, &fd) < 0) ||
      (argint(6, &offset) < 0))
    return 0;
  addr = (int)mmap((void *)addr, len, prot, flags, fd, offset);
  if (addr == -1)
    return 0;
  return addr;
}
```

```C
int sys_munmap(void) {
  int addr, len;
  if ((argint(0, &addr) < 0) ||
      (argint(1, &len) < 0))
    return -1;
  return munmap((void *)addr, len);
}
```

---
Parts of the following sections inspired by https://pdos.csail.mit.edu/6.828/2012/homework/xv6-zero-fill.html.


## Lazy page allocation
In this section, we'll need to change the current behavior of **mmap()** from immediate allocation (**kalloc()**) and map ping (**mappages()**) of physical memory pages to lazy page allocation, where pages are only allocated when a pagefault occurs during access.

Benefits of lazy page allocation over immediate page allocation:

- Some programs allocate memory but never use it, for example, to implement large sparse arrays. Lazy page allocation allows us to avoid spending time and physical memory allocating and mapping the entire region.
- We can allow programs to map regions bigger than the amount of physical memory available so the operating system can provide the illusion of unlimited resources.

## mmap()
We no longer need to call **allocuvm()** and **memset()** when **mmap()** is called. We only need to keep track of reserved regions large enough to accommodate calls to **mmap()**. It is not until the user encounters a page fault while trying to access a mapped region, do we actually allocate the region being accessed.

To handle page faults, we’ll need to edit **trap()** in **trap.c**, which contains the code that handles traps. Beyond the code that handles hardware interrupts, we can add code to check if the trap number corresponds to a page fault. This number has been predefined in **traps.h** as **T_PGFLT**.

In **mmap.c**:
```C
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
```

In **trap.c**:
```C
switch(tf->trapno){
  ...
  case T_PGFLT:
    pagefault_handler(tf);
    break;
  ...
```

If the trap number is indeed equal to **T_PGFLT**, we can call **pagefault_handler()**. This function checks if the fault address was previously reserved by **mmap()** by searching the process’ maplist, a linked list of memory mapped regions, for a match. If a match is found, then we go ahead and begin a routine with code borrowed from **allocuvm()**. The main difference between **allocuvm()** and the code used in **pagefault_handler()** that maps pages for the faulted region is a section that checks write permissions on the pages. We want to default to read-only pages while **allocuvm()** grants write permissions by default.

In the next section, we discuss the section of code that handles file-backed pages. We also have a helper function in **mmap.c()**, **ml_find()**, which checks if the fault address matches any entries in the process map list. If so, a pointer to the map list entry is returned. We also add a new allocated flag to our maplist entry which indicates whether or not **kalloc()** has been called for that specific region. This allows us to avoid page faults when we **munmap()** a region that has not yet been allocated. Therefore, when we allocate the mmapped region in **pagefault_handler()**, we can set the allocated flag to 1.

```C
struct maplist * ml_find(void *addr) {
  struct maplist *p = myproc()->ml;

  while (p && p->addr != addr)
    p = p->next;
  
  return p;
}
```

In **trap.c**:
```C
void pagefault_handler(struct trapframe *tf) {
  struct proc *curproc = myproc();
  uint fault_addr = rcr2();
  void *start = (void*)PGROUNDDOWN(fault_addr);
  struct maplist *ml_entry = NULL;
  int length;


  cprintf("============in pagefault_handler============\n");
  cprintf("pid %d %s: trap %d err %d on cpu %d "
          "eip 0x%x addr 0x%x\n", curproc->pid, curproc->name, tf->trapno, tf->err, cpuid(), tf->eip, fault_addr);

  if ((ml_entry = ml_find(start)) == NULL) {
    cprintf("Did not find a matching starting address with 0x%x in maplist\n", start);
    exit();
  }

  length = ml_entry->len;

  // allocuvm with read-only default
  uint oldsz = (uint)start;
  uint newsz = oldsz+length;
  char *mem;
  uint a;
  int mappages_ret;

  if(newsz >= KERNBASE)
    exit();
  if(newsz < oldsz)
    exit();

  // begin allocuvm
  a = oldsz;
  for(; a < newsz; a += PGSIZE){
    mem = kalloc();
    if(mem == 0){
      deallocuvm(curproc->pgdir, newsz, oldsz);
      exit();
    }
    memset(mem, 0, PGSIZE);
    // check write permissions
    if ((ml_entry->prot & PROT_WRITE) == PROT_WRITE) {
      if (ml_entry->allocated == 1) {
        cprintf("remap 1\n");
        exit();
      }
      mappages_ret = mappages(curproc->pgdir, (char*)a, PGSIZE, V2P(mem), PTE_W|PTE_U);
    } else {
      if (ml_entry->allocated == 1) {
        cprintf("remap 2\n");
        exit();
      }
      mappages_ret = mappages(curproc->pgdir, (char*)a, PGSIZE, V2P(mem), PTE_U);
    }
    
    if(mappages_ret < 0){
      deallocuvm(curproc->pgdir, newsz, oldsz);
      kfree(mem);
      exit();
    } 
  }
  // end allocuvm
```

## File-backed mmap()

We first add a function in **file.c** called **fileseek()** which allows the user to change the offset field in a file
struct. To do this, we first have to acquire a lock to avoid race conditions.

```C
int fileseek(struct file* f, uint offset) {
  if(f->type == FD_INODE){
    ilock(f->ip);
    f->off = offset;
    iunlock(f->ip);
    return 0;
  }
  return -1;
}
```

Our protection and region type flags are defined below. The definitions are mostly arbitrary while **MAP_ANONYMOUS** is borrowed from the POSIX memory mapping definitions for Linux.

In **mman.h**:
```C
#define PROT_WRITE      0x01            /* Page can be written.  */
#define MAP_FILE 0x01
#define MAP_ANONYMOUS   0x20            /* Don't use a file.  */
```

In our **mmap()** function (see page 1), we need to perform flag checks for our memory regions. If **MAP_ANONYMOUS** is passed, fd must be -1. Otherwise, we must have a valid fd for **MAP_FILE**. We can use similar error checking found in the **argfd()** function to check that the int in fd does not exceed the maximum number of open files possible. If the file is readable and writable, we duplicate the file descriptor with **filedup()** and save the duplicated file descriptor with our maplist entry. While we save the protection flags in our maplist, we don’t actually set protections on the region until **page_faulthandler()** and subsequently, **mappages()** is called, which is where the memory allocation really occurs.

In **munmap()**, we make sure to handle the cases where a valid file descriptor is present in the maplist
entry and the region has been allocated by **kalloc()**. If the region has not yet been allocated (ie a page
fault has not occurred in the region yet), we skip the deallocation process.

```C
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
```

To allow a user to force a write from the file-backed regions to the actual files, we need to create an **msync()** system call. As usual, we’ll need to modify the **usys.S**, **syscall.h**, **syscall.c** and **sysfile.c** files.

In order to optimize **msync()**, we can check for the dirty bit of page table entries. According to the [xv6 manual] (https://pdos.csail.mit.edu/6.828/2019/xv6/book-riscv-rev0.pdf), the dirty bit corresponds to bit 6 (from the least significant end) of a page table entry.

In **mmu.h** we define a macro that helps us check the k’th bit of an address and another defining the dirty bit in a page table entry.

```C
#define CHECKBIT(a,k) ((a) & (1 << k))
#define PTE_D 0x006 // Dirty
```

For the sake of optimization, we only write pages if the dirty bit in the PTE is set. To get the PTE, we can use **walkpgdir()**. Once we’ve confirmed the PTE is valid, we make sure the page has been written to before bothering to sync the write to the file. This can be done by checking for **PTE_D** with the help of the macro we defined earlier. We use
**filewrite()** which will make sure not to write past the file size.

Each time **msync()** is called, we need to reset the file offset before writing to the file so we don’t simply concatenate our data to the end.

In **mmap.c**:
```C
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
      filewrite(f, (char *)a, PGSIZE);
    }
  }

  return 0;
}
```
