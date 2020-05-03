#include "types.h"
#include "x86.h"
#include "defs.h"
#include "date.h"
#include "param.h"
#include "memlayout.h"
#include "mmu.h"
#include "proc.h"

int
sys_fork(void)
{
  return fork();
}

int
sys_exit(void)
{
  exit();
  return 0;  // not reached
}

int
sys_wait(void)
{
  return wait();
}

int
sys_kill(void)
{
  int pid;

  if(argint(0, &pid) < 0)
    return -1;
  return kill(pid);
}

int
sys_getpid(void)
{
  return myproc()->pid;
}

int
sys_sbrk(void)
{
  int addr;
  int n;

  if(argint(0, &n) < 0)
    return -1;
  addr = myproc()->sz;
  if(growproc(n) < 0)
    return -1;
  return addr;
}

int
sys_sleep(void)
{
  int n;
  uint ticks0;

  if(argint(0, &n) < 0)
    return -1;
  acquire(&tickslock);
  ticks0 = ticks;
  while(ticks - ticks0 < n){
    if(myproc()->killed){
      release(&tickslock);
      return -1;
    }
    sleep(&ticks, &tickslock);
  }
  release(&tickslock);
  return 0;
}

// return how many clock tick interrupts have occurred
// since start.
int
sys_uptime(void)
{
  uint xticks;

  acquire(&tickslock);
  xticks = ticks;
  release(&tickslock);
  return xticks;
}


// kernel memory allocation
int sys_kmalloc(void) {
  int n;
  void *p;
  if(argint(0, &n) < 0)
    return -1;
  if ((int)(p = kmalloc((uint)n)) == 0)
    return -1;
  return (int)p;
}

int sys_kmfree(void) {
  int a;
  if(argint(0, &a) < 0)
    return -1;
  kmfree((char *)a);
  return 0;
}


// mmap
int sys_mmap(void) {
  int addr, len, prot, flags, fd, offset;
  if ((argint(0, &addr) < 0) ||
      (argint(1, &len) < 0) ||
      (argint(2, &prot) < 0) ||
      (argint(3, &flags) < 0) ||
      (argint(4, &fd) < 0) ||
      (argint(5, &offset) < 0))
    return 0;
  addr = (int)mmap((void *)addr, len, prot, flags, fd, offset);
  if (addr == -1)
    return 0;
  return addr;
}

int sys_munmap(void) {
  int addr, len;
  if ((argint(0, &addr) < 0) ||
      (argint(1, &len) < 0))
    return -1;
  return munmap((void *)addr, len);
}
