#include "types.h"
#include "defs.h"
#include "param.h"
#include "memlayout.h"
#include "mmu.h"
#include "proc.h"
#include "x86.h"
#include "traps.h"
#include "spinlock.h"
#include "mmap.h"
#include "mman.h"

// Interrupt descriptor table (shared by all CPUs).
struct gatedesc idt[256];
extern uint vectors[];  // in vectors.S: array of 256 entry pointers
struct spinlock tickslock;
uint ticks;

void
tvinit(void)
{
  int i;

  for(i = 0; i < 256; i++)
    SETGATE(idt[i], 0, SEG_KCODE<<3, vectors[i], 0);
  SETGATE(idt[T_SYSCALL], 1, SEG_KCODE<<3, vectors[T_SYSCALL], DPL_USER);

  initlock(&tickslock, "time");
}

void
idtinit(void)
{
  lidt(idt, sizeof(idt));
}


// Handles page faults
// Checks if page fault address can be found in processes' linked list of reserved mmapped regions
// If so, allocates memory for the region
void pagefault_handler(struct trapframe *tf) {
  struct proc *curproc = myproc();
  uint fault_addr = rcr2();
  void *start = (void*)PGROUNDDOWN(fault_addr);
  struct maplist *ml_entry = NULL;
  int length;


  cprintf("============in pagefault_handler============\n");
  cprintf("pid %d %s: trap %d err %d on cpu %d "
          "eip 0x%x addr 0x%x\n", curproc->pid, curproc->name, tf->trapno, tf->err, cpuid(), tf->eip, fault_addr);
  //ml_print();
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
    //cprintf("a: 0x%x, oldsz: 0x%x, newsz: 0x%x\n",a, oldsz, newsz);
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

  // after allocating, if fd present, read file into region
  if (ml_entry->allocated == 0 && ml_entry->fd != NULL) {
    //cprintf("entering fileread with start: 0x%x, offset: %d, length: 0x%x\n", start, ml_entry->offset, length);
    fileread((struct file *)ml_entry->fd, start, length);

    pde_t *pte = NULL;
    if((pte = walkpgdir(curproc->pgdir, (void *)start, 0)) == NULL) { // find pte corresponding to start
      cprintf("Failed to find pte to unset dirty bit\n");
      exit();
    }
    *pte &= ~(1 << PTE_D); // unset dirty bit
  }

  ml_entry->allocated = 1;
  return;
}



//PAGEBREAK: 41
void
trap(struct trapframe *tf)
{
  if(tf->trapno == T_SYSCALL){
    if(myproc()->killed)
      exit();
    myproc()->tf = tf;
    syscall();
    if(myproc()->killed)
      exit();
    return;
  }

  switch(tf->trapno){
  case T_IRQ0 + IRQ_TIMER:
    if(cpuid() == 0){
      acquire(&tickslock);
      ticks++;
      wakeup(&ticks);
      release(&tickslock);
    }
    lapiceoi();
    break;
  case T_IRQ0 + IRQ_IDE:
    ideintr();
    lapiceoi();
    break;
  case T_IRQ0 + IRQ_IDE+1:
    // Bochs generates spurious IDE1 interrupts.
    break;
  case T_IRQ0 + IRQ_KBD:
    kbdintr();
    lapiceoi();
    break;
  case T_IRQ0 + IRQ_COM1:
    uartintr();
    lapiceoi();
    break;
  case T_IRQ0 + 7:
  case T_IRQ0 + IRQ_SPURIOUS:
    cprintf("cpu%d: spurious interrupt at %x:%x\n",
            cpuid(), tf->cs, tf->eip);
    lapiceoi();
    break;

  // page fault
  case T_PGFLT:
    pagefault_handler(tf);
    break;

  //PAGEBREAK: 13
  default:
    if(myproc() == 0 || (tf->cs&3) == 0){
      // In kernel, it must be our mistake.
      cprintf("unexpected trap %d from cpu %d eip %x (cr2=0x%x)\n",
              tf->trapno, cpuid(), tf->eip, rcr2());
      panic("trap");
    }
    // In user space, assume process misbehaved.
    cprintf("pid %d %s: trap %d err %d on cpu %d "
            "eip 0x%x addr 0x%x--kill proc\n",
            myproc()->pid, myproc()->name, tf->trapno,
            tf->err, cpuid(), tf->eip, rcr2());
    myproc()->killed = 1;
  }

  // Force process exit if it has been killed and is in user space.
  // (If it is still executing in the kernel, let it keep running
  // until it gets to the regular system call return.)
  if(myproc() && myproc()->killed && (tf->cs&3) == DPL_USER)
    exit();

  // Force process to give up CPU on clock tick.
  // If interrupts were on while locks held, would need to check nlock.
  if(myproc() && myproc()->state == RUNNING &&
     tf->trapno == T_IRQ0+IRQ_TIMER)
    yield();

  // Check if the process has been killed since we yielded
  if(myproc() && myproc()->killed && (tf->cs&3) == DPL_USER)
    exit();
}