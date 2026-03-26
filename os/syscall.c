#include <stddef.h>
#include "syscall.h"
#include "defs.h"
#include "loader.h"
#include "syscall_ids.h"
#include "timer.h"
#include "trap.h"
#include "proc.h"
#include "vm.h"

uint64 sys_write(int fd, uint64 va, uint len)
{
	debugf("sys_write fd = %d va = %x, len = %d", fd, va, len);
	if (fd != STDOUT)
		return -1;
	struct proc *p = curr_proc();
	char str[MAX_STR_LEN];
	int size = copyinstr(p->pagetable, str, va, MIN(len, MAX_STR_LEN));
	debugf("size = %d", size);
	for (int i = 0; i < size; ++i) {
		console_putchar(str[i]);
	}
	return size;
}

__attribute__((noreturn)) void sys_exit(int code)
{
	exit(code);
	__builtin_unreachable();
}

uint64 sys_sched_yield()
{
	yield();
	return 0;
}

uint64 sys_getpid()
{
    struct proc *p = curr_proc();
    return p->pid;
}



uint64 sys_gettimeofday(TimeVal *val, int _tz) // TODO: implement sys_gettimeofday in pagetable. (VA to PA)
{
	// // YOUR CODE
	// val->sec = 0;
	// val->usec = 0;

	// /* The code in `ch3` will leads to memory bugs*/

	// // uint64 cycle = get_cycle();
	// // val->sec = cycle / CPU_FREQ;
	// // val->usec = (cycle % CPU_FREQ) * 1000000 / CPU_FREQ;
    
	struct proc *p = curr_proc();

	// convert user VA -> PA 
	uint64 pa = useraddr(p->pagetable, (uint64)val);
    if (pa == 0) return -1;

    TimeVal *kval = (TimeVal *)pa;
    uint64 cycle = get_cycle();
    kval->sec  = cycle / CPU_FREQ;
    kval->usec = (cycle % CPU_FREQ) * 1000000 / CPU_FREQ;

	return 0;
}

// TODO: add support for mmap and munmap syscall.
// hint: read through docstrings in vm.c. Watching CH4 video may also help.
// Note the return value and PTE flags (especially U,X,W,R)
/*
* LAB1: you may need to define sys_task_info here
*/

uint64 sys_task_info(struct TaskInfo *ti) {
    if (ti == 0)
    {
        return -1;
    }


    struct proc *p = curr_proc();
    if (p == 0)
    {
        return -1;
    }

	// convert user VA -> PA 
	uint64 pa = useraddr(p->pagetable, (uint64)ti);
    if (pa == 0) 
	{
		return -1;
	}
	
	struct TaskInfo *kti = (struct TaskInfo *)pa;

    // matching the process state with the TaskInfo state (TaskStatus)
    switch (p->state) {
        case UNUSED:
        case USED:
            kti->status = UnInit;
            break;
        case RUNNABLE:
            kti->status = Ready;
            break;
        case RUNNING:
            kti->status = Running;
            break;
        case ZOMBIE:
            kti->status = Exited;
            break;
        default:
            kti->status = UnInit;
            break;
    }
       
    // copying syscall counts
    for (int i = 0; i < MAX_SYSCALL_NUM; i++)
    {
        kti->syscall_times[i] = p->syscall_times[i];
    }

    uint64 current_cycle = get_cycle();
    uint64 elapsed_cycles = current_cycle - p->start_time;
    kti->time = (int)((elapsed_cycles * 1000) / CPU_FREQ); // in ms
   
    return 0;
}


// 
uint64 sys_mmap(uint64 start, uint64 len, int port, int flag, int fd)
{
	// if there is nothing to map
	if (len == 0) return 0;

	// start must sit on a page boundary
	if (start % PGSIZE != 0) return -1;
	
	
	// upper bits of port must be zero
	if (port & ~0x7) return -1;

	// at least one permission must be set 
	if ((port & 0x7) == 0) return -1;
	
	// round len up to the next page boundary
	len = PGROUNDUP(len);

	// page table entry permission flags for port argument
	int perm = PTE_U;
    if (port & 1) perm |= PTE_R;
    if (port & 2) perm |= PTE_W;
    if (port & 4) perm |= PTE_X;

	struct proc *p = curr_proc();
	// checking if the pages in [start, start + len) already been mapped
	for (uint64 va = start; va < start + len; va += PGSIZE) {
		//Return the address of the PTE in page table pagetable
        pte_t *pte = walk(p->pagetable, va, 0);
        if (pte != 0 && (*pte & PTE_V)) {
            return -1;  // this virtual page already has a live mapping
        }
    }

	// allocating and map one PA/VA
	for (uint64 va = start; va < start + len; va += PGSIZE) {
		void *pa = kalloc();
		if (pa == 0) return -1; 
		// zero the page before giving it to user space
		memset(pa, 0, PGSIZE);
		if (mappages(p->pagetable, va, PGSIZE, (uint64)pa, perm) != 0) {
            // mappages failed (e.g., couldn't allocate an intermediate
            // page-table node).  Free the physical page we just got or
            // it leaks — it's off the free list but not mapped anywhere.
            kfree(pa);
            return -1;
        }
		
	}
	return 0;
}

uint64 sys_munmap(uint64 start, uint64 len)
{
	
	if (len == 0) return 0;

	// start must sit on a page boundary
	if (start % PGSIZE != 0) return -1;

	len = PGROUNDUP(len);
	struct proc *p = curr_proc();

	// check if any page in [start, start+len) unmapped
    for (uint64 va = start; va < start + len; va += PGSIZE) {
        pte_t *pte = walk(p->pagetable, va, 0);
        if (pte == 0 || !(*pte & PTE_V)) {
            return -1;  // found an unmapped page — reject the whole call
        }
    }

	uint64 npages = len / PGSIZE;
	
    uvmunmap(p->pagetable, start, npages, 1);
    return 0;

}

extern char trap_page[];

void syscall()
{
	struct trapframe *trapframe = curr_proc()->trapframe;
	int id = trapframe->a7, ret;
	uint64 args[6] = { trapframe->a0, trapframe->a1, trapframe->a2,
			   trapframe->a3, trapframe->a4, trapframe->a5 };
	tracef("syscall %d args = [%x, %x, %x, %x, %x, %x]", id, args[0],
	       args[1], args[2], args[3], args[4], args[5]);
	/*
	* LAB1: you may need to update syscall counter for task info here
	*/
	struct proc *p = curr_proc();
	if (id >= 0 && id < MAX_SYSCALL_NUM)
	{
		p->syscall_times[id]++;
	}		

	switch (id) {
	case SYS_write:
		ret = sys_write(args[0], args[1], args[2]);
		break;
	case SYS_exit:
		sys_exit(args[0]);
		// __builtin_unreachable();
	case SYS_sched_yield:
		ret = sys_sched_yield();
		break;
	case SYS_gettimeofday:
		ret = sys_gettimeofday((TimeVal *)args[0], args[1]);
		break;
	/*
	* LAB1: you may need to add SYS_taskinfo case here
	*/
    case SYS_task_info:
        ret = sys_task_info((struct TaskInfo *)args[0]);
        break;
    case SYS_getpid:
        ret = sys_getpid((struct TaskInfo *)args[0]);
        break;

	case SYS_mmap:
		ret = sys_mmap(args[0], args[1], (int)args[2], (int)args[3], (int)args[4]);
		break;
	case SYS_munmap:
		ret = sys_munmap(args[0], args[1]);
		break;
	default:
		ret = -1;
		errorf("unknown syscall %d", id);
	}
	trapframe->a0 = ret;
	tracef("syscall ret %d", ret);
}
