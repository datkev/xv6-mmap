# xv6-mmap
mmap implementation on top of xv6

Steps to implementing a file-backed **mmap()**:
1. Add a memory allocator for the kernel via **kmalloc()** and **kmfree()**
2. Add a linked list to keep track of memory mappings from **mmap()**
3. Add anonymous **mmap()** (not file-backed)
4. Add file-backing capabilities to **mmap()**

## kmalloc()
In this section, we build a memory allocator for the kernel. We already have a user-space allocator, **umalloc()**, 
so we borrow much of the existing code from K&R’s **umalloc()** and make some modifications. Unlike memory allocated
for user-space, memory allocated for the kernel is not freed upon termination of the process. This way, the kernel is
safe to use the allocated memory without risk of losing data when a process is terminated.

Currently, the **morecore()** call within **umalloc()** allocates a minimum of 4096 units of size,
sizeof(Header), by calling **sbrk()**. In **kmalloc()**, since we don’t want to grow user space
by calling **sbrk()** (which calls **growproc()**), we call **kalloc()** directly to allocate a page of memory for the kernel.

This page will be added to a list of memory chunks, reserved for kernel use, to be distributed by our function
**kmalloc()**. Maintaining a list of unallocated memory allows us to distribute from this list anytime a call
to **kmalloc()** is made without necessarily having to make a new call to **kalloc()**. As long as the call to **kmalloc()**
requests for a size of memory equal to or less than the size of an existing chunk in our free list, we can reuse unallocated 
memory from previous calls to **kalloc()**.

The structure of our free list remains the same as the **umalloc()** free list. We leave the definition of the
union header out for brevity.

We assume that the call to **kmalloc()** is limited to 4096 bytes, so we add a panic if the request is greater
than a page in length.

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

In **kmalloc()**, if we find that our free list does not contain a chunk of memory large enough for the
current request, we call **kmorecore()**, a modified version of **morecore()** which calls **kalloc()** instead of **sbrk()**. 
Since **kalloc()** allocates 4096 bytes, we need adjust the size in the header to specify the number of header-sized units the chunk contains.

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

The code for kmfree does not change from the code for K&R’s free. In a nutshell, the **kmfree()** code
assumes the free list is in increasing order of addresses within the kernel space. If the chunk to be freed
is adjacent to a chunk in the list, it merges with the adjacent chunk. It is possible for the chunk to merge
with two adjacent chunks in the list. If the chunk cannot be merged, then it is placed at the appropriate
location within the list, maintaining the invariant of increasing addresses.


## Adding system calls

As usual, our system calls will need to modify the **usys.S**, **syscall.h**, and **syscall.c** files. We can fetch
the system call arguments using wrappers defined in **sysproc.c**. Note that we can’t use **argptr** for
**kmfree()** since **argptr** checks if the pointer is within the user process space. Since **kmalloc()** will be
returning addresses in kernel space, calls to **kmfree()** will need to pass pointers with addresses in kernel
space.

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
In this section, we construct the data structure used to keep track of the memory mappings allocated by mmap.
The data structure we use is a linked list that maintains an increasing order of addresses for the mapped
pages provided in **mmap.h**.

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
In addition, in fork, child processes inherit the map list from parent processes.
```C
np->ml = curproc->ml;
```


## mmap()

Within **mmap.c**, the **mmap()** function uses **allocuvm()** to grow the process’ user space, taking the **addr**
argument as a hint for a starting address for the new region. We define **MMAPBASE** to be `0x4000000`,
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

When it comes time to unmap a mapped region, we can call munmap, which will first search for a
mapped region in our map list matching the addr and length arguments. Assuming we find a matching
region, we then clear the region using memset. Then, using **deallocuvm()**, we unmap the memory region
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

