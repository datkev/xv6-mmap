#include "types.h"
#include "stat.h"
#include "defs.h"
#include "param.h"

// Kernel memory allocator with original code from
// memory allocator by Kernighan and Ritchie,
// The C programming Language, 2nd ed.  Section 8.7.

typedef long Align;

union header {
  struct {
    union header *ptr;
    uint size;
  } s;
  Align x;
};

typedef union header Header;

static Header base;
static Header *freep;


void kmfree(void *ap) {
  Header *bp, *p;

  bp = (Header*)ap - 1;                                       // point to block header
  for(p = freep; !(bp > p && bp < p->s.ptr); p = p->s.ptr)    // freelist is in increasing address order
    if(p >= p->s.ptr && (bp > p || bp < p->s.ptr))            // hit the end of list
      break;
  if(bp + bp->s.size == p->s.ptr){                            // join upper neighbor
    bp->s.size += p->s.ptr->s.size;                           // adjust size, adjust next ptr
    bp->s.ptr = p->s.ptr->s.ptr;                              
  } else                                                      // does not join upper
    bp->s.ptr = p->s.ptr;                                      
  if(p + p->s.size == bp){                                    // join lower neighbor
    p->s.size += bp->s.size;                                  // adjust size of prev, adjust next ptr of prev
    p->s.ptr = bp->s.ptr;                                     
  } else                                                      // only if goes in between
    p->s.ptr = bp;                                            
  freep = p;
}


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
      //cprintf("returning p: 0x%x. p.size: %d. p.next: 0x%x\n",p,p->s.size, p->s.ptr);
      return (void*)(p + 1);                                    // return free region after header
    }
    if(p == freep)                                              // full cycle
      if((p = kmorecore()) == 0)
        return 0;
  }
}


void kmprint() {
  Header *p;
  if (freep == 0) { // degenerate list
    base.s.ptr = &base;                         
    base.s.size = 0;
  }
  p = &base;
  cprintf("===kmprint:===\n");
  cprintf("[address: %x, size: %d]", p, p->s.size*sizeof(Header));
  p = p->s.ptr;
  while (p != &base) {
    cprintf("-->[address: %x, size: %d]-->", p, p->s.size*sizeof(Header));
    p = p->s.ptr;
  }
  cprintf("head\n");
  cprintf("=== end km alloc list===\n");
}