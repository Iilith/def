#include<linux/module.h>
#include "libs/ftrace_module.h"

unsigned long *__sysc_table;

unsigned long *ret_sysc_table(void)
{
	__sysc_table = (unsigned long *)kallsyms_lookup_name("sys_call_table");
	return __sysc_table;
}

static int __init sysc_init(void)
{
  unsigned long *__sysc = ret_sysc_table();
  return 0;
}

static void __exit sysc_destroy(void)
{
  // exit shit here
}

module_init(sysc_init);
module_exit(sysc_destroy);
