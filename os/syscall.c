#include "syscall.h"
#include "console.h"
#include "defs.h"
#include "loader.h"
#include "syscall_ids.h"
#include "timer.h"
#include "trap.h"

uint64 sys_write(int fd, uint64 va, uint len)
{
	debugf("sys_write fd = %d str = %x, len = %d", fd, va, len);
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

uint64 sys_read(int fd, uint64 va, uint64 len)
{
	debugf("sys_read fd = %d str = %x, len = %d", fd, va, len);
	if (fd != STDIN)
		return -1;
	struct proc *p = curr_proc();
	char str[MAX_STR_LEN];
	for (int i = 0; i < len; ++i) {
		int c = consgetc();
		str[i] = c;
	}
	copyout(p->pagetable, va, str, len);
	return len;
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

uint64 sys_gettimeofday(uint64 val, int _tz)
{
	struct proc *p = curr_proc();
	uint64 cycle = get_cycle();
	TimeVal t;
	t.sec = cycle / CPU_FREQ;
	t.usec = (cycle % CPU_FREQ) * 1000000 / CPU_FREQ;
	copyout(p->pagetable, val, (char *)&t, sizeof(TimeVal));
	return 0;
}

uint64 sys_getpid()
{
	return curr_proc()->pid;
}

uint64 sys_getppid()
{
	struct proc *p = curr_proc();
	return p->parent == NULL ? IDLE_PID : p->parent->pid;
}

uint64 sys_clone()
{
	debugf("fork!\n");
	return fork();
}

uint64 sys_exec(uint64 va)
{
	struct proc *p = curr_proc();
	char name[200];
	copyinstr(p->pagetable, name, va, 200);
	debugf("sys_exec %s\n", name);
	return exec(name);
}

uint64 sys_wait(int pid, uint64 va)
{
	struct proc *p = curr_proc();
	int *code = (int *)useraddr(p->pagetable, va);
	return wait(pid, code);
}

uint64 sys_spawn(uint64 va)
{
	// TODO: your job is to complete the sys call
	struct proc *p = curr_proc();

    char name[200];

    // copy filename from user space safely
    if (copyinstr(p->pagetable, name, va, 200) < 0)
        return -1;

    // call real kernel spawn logic
    return spawn(name);
}

uint64 sys_set_priority(long long prio){
    // TODO: your job is to complete the sys call
	if (prio < 2)
		return -1;
	
	struct proc *p = curr_proc();
	p->priority = prio;
	p->pass = BIG_STRIDE/prio;

	return prio;
}


uint64 sys_task_info(uint64 va)
{
    struct proc *p = curr_proc();
    if (p == NULL)
        return -1;

    struct TaskInfo ti;

    // map state
    switch (p->state) {
        case UNUSED:
        case USED:
            ti.status = UnInit;
            break;
        case RUNNABLE:
            ti.status = Ready;
            break;
        case RUNNING:
            ti.status = Running;
            break;
        case ZOMBIE:
            ti.status = Exited;
            break;
        default:
            ti.status = UnInit;
            break;
    }

    // no syscall_times -> zeros
    for (int i = 0; i < MAX_SYSCALL_NUM; i++)
        ti.syscall_times[i] = 0;

    //start_time -> approximate or set 0
    ti.time = 0;

    // copy to user space
    if (copyout(p->pagetable, va, (char *)&ti, sizeof(ti)) < 0)
        return -1;

    return 0;
}

uint64 sys_mmap(uint64 start, uint64 len, int port, int flag, int fd)
{
    //   Guard 1: len=0 means "map nothing", which is valid        
    if (len == 0)
        return 0;

    //   Guard 2: start must sit on a page boundary              
    if (start % PGSIZE != 0)
        return -1;

    //   Guard 3: upper bits of port must be zero               
    if (port & ~0x7)
        return -1;

    //   Guard 4: at least one permission must be set             
    if ((port & 0x7) == 0)
        return -1;

    //   Round len up to the next page boundary                
    len = PGROUNDUP(len);

    //   Build PTE permission flags from the port argument         
    int perm = PTE_U;
    if (port & 1) perm |= PTE_R;
    if (port & 2) perm |= PTE_W;
    if (port & 4) perm |= PTE_X;

    struct proc *p = curr_proc();

    //   Pre-check: no page in [start, start+len) may already be mapped  
    for (uint64 va = start; va < start + len; va += PGSIZE) {
        // using useraddress instead of walk() in ch4
		if (useraddr(p->pagetable, va) != 0) {
			return -1;
		}
    }

    //   Allocate and map one physical page per virtual page        
    for (uint64 va = start; va < start + len; va += PGSIZE) {
        // Get one free physical page from the kernel allocator.
        void *pa = kalloc();
        if (pa == 0) {
            return -1;
        }

        // Zero the page before giving it to user space.
        memset(pa, 0, PGSIZE);

        // Write one PTE: virtual page at 'va' → physical page at 'pa'.
        if (mappages(p->pagetable, va, PGSIZE, (uint64)pa, perm) != 0) {
            kfree(pa);
            return -1;
        }
    }

    return 0;
}

uint64 sys_munmap(uint64 start, uint64 len)
{
    //   Guard 1: len=0, nothing to unmap                 
    if (len == 0)
        return 0;

    //   Guard 2: start must be page-aligned               
    if (start % PGSIZE != 0)
        return -1;

    //   Round len up                           
    len = PGROUNDUP(len);

    struct proc *p = curr_proc();

    //   Pre-check: every page in [start, start+len) must be mapped    
	for (uint64 va = start; va < start + len; va += PGSIZE) {
		if (walkaddr(p->pagetable, va) == 0) {
			return -1;
		}
	}

    //   Unmap and free every page in the range              
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
	switch (id) {
	case SYS_write:
		ret = sys_write(args[0], args[1], args[2]);
		break;
	case SYS_read:
		ret = sys_read(args[0], args[1], args[2]);
		break;
	case SYS_exit:
		sys_exit(args[0]);
		// __builtin_unreachable();
	case SYS_sched_yield:
		ret = sys_sched_yield();
		break;
	case SYS_gettimeofday:
		ret = sys_gettimeofday(args[0], args[1]);
		break;
	case SYS_getpid:
		ret = sys_getpid();
		break;
	case SYS_getppid:
		ret = sys_getppid();
		break;
	case SYS_clone: // SYS_fork
		ret = sys_clone();
		break;
	case SYS_execve:
		ret = sys_exec(args[0]);
		break;
	case SYS_wait4:
		ret = sys_wait(args[0], args[1]);
		break;
	case SYS_spawn:
		ret = sys_spawn(args[0]);
		break;
	case SYS_mmap:
		ret = sys_mmap(args[0], args[1], (int)args[2], (int)args[3], (int)args[4]);
		break;
	case SYS_setpriority:
		ret = sys_set_priority(args[0]);
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
