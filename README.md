# xv6-mmap
mmap implementation on top of xv6


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


## kmorecore()

In **kmalloc()**, if we find that our free list does not contain a chunk of memory large enough for the
current request, we call **kmorecore()**, a modified version of **morecore()** which calls **kalloc()** instead of **sbrk()**. 
Since **kalloc()** allocates 4096 bytes, we need adjust the size in the header to specify the number of header-sized units the chunk contains.


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


## maplist struct

We first construct the data structure used to keep track of the memory mappings allocated by mmap.
The data structure we use is a linked list that maintains an increasing order of addresses for the mapped
pages provided in **mmap.h**.

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
argument as a hint for a starting address for the new region. We define **MMAPBASE** to be 0x4000000,
meaning all mmapped regions will be mapped beyond **0x4000000** (halfway to KERNBASE). In order
to take the user-supplied address as a “hint”, the function **ml_get_next()** finds the next available page-
aligned address using the user-supplied addr as an offset from **MMAPBASE**. If we cannot find an
address between **MMAPBASE** and **KERNBASE**, using **addr** as an offset, **mmap()** fails. Using
**memset()**, we clear the newly mapped region and add a new element to our map list based on the
attributes (arguments) of the region. If we don’t have enough space in the kernel to store the new list
element, we need to be sure to deallocate the allocated region.


## maplist helpers

For each memory mapped region, we keep track of the starting address, length, region type, offset, and
hold a duplicate of the file descriptor. Any time a call to **mmap()** is made, we add a list element with this
metadata for the mapping. As mentioned before, elements are ordered in increasing order of mapped
page address, so we can perform a linear scan for insertion and deletion.


## munmap()

When it comes time to unmap a mapped region, we can call munmap, which will first search for a
mapped region in our map list matching the addr and length arguments. Assuming we find a matching
region, we then clear the region using memset. Then, using **deallocuvm()**, we unmap the memory region
in page sized chunks. Finally, we need to free the list element tracking the mapped region using
**kmfree()**.


## Adding more system calls

In order to add the system calls, will need to modify the **usys.S**, **syscall.h**, and **syscall.c** files. As
before, we can fetch the system call arguments using wrappers defined in **sysproc.c**. We note that the
failure code for **sys_mmap()** is 0 for compatibility with test cases.
