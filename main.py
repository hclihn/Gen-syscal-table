#!/usr/bin/env python
import os
import sys
import re
import subprocess

# Source: https://github.com/nelhage/ministrace/blob/master/gen_tables.py
# Linux source has changed so much that this doesn't work!

# syscall table file is preferred!
USE_SYSCALL_TBL = True

def parse_tbl_file(tbl_file):
  syscalls = {}
  for line in open(tbl_file):
    line = line.strip()
    if len(line) == 0 or line.startswith('#'):
      continue
    # <number> <abi> <name> <entry point> [<compat entry point>]
    fields = line.split()
    number = int(fields[0])
    if len(fields) < 4:
      print("-> unimplemented syscall %d" % (number))
      continue
    syscalls[number] = {
      'Number': number, 
      'Name': fields[2],
      'EntryPoint': fields[3],
      'Implementation': fields[1], # common, i386, x32, 64 
      }
  return syscalls

def do_syscall_numbers(syscalls_xx_file):
    syscalls = {}
    for line in open(syscalls_xx_file):
        line = line.strip()
        # __SYSCALL(10, sys_unlink)
        # __SYSCALL_WITH_COMPAT(11, sys_execve, compat_sys_execve)
        m = re.search(r'^__SYSCALL(?:[A-Z_]+)?\(([0-9]+),\s*sys_([a-z_0-9]+)(?:,\s+([a-z_0-9]+))?\)', line)
        if m:
            (number, name, compat) = m.groups()
            number = int(number)
            if name == "ni_syscall":
              print("-> unimplemented syscall %d" % (number))
              continue
            syscalls[number] = {
              'Number': number,
              'Name': name,
              'EntryPoint': "sys_"+name,
              'Implementation': compat or "",
            }
    return syscalls

def find_args(syscalls_file, syscalls):
    sys_funcs = {}
    cont = False
    the_line = ''
    for line in open(syscalls_file):
      line = line.strip()
      if cont:
        the_line += line
        if line.endswith(';'):
          cont = False
        else:
          continue
      elif line.startswith('asmlinkage '):
        the_line = line
        if not line.endswith(';'):
          cont = True
          continue
      else:
        the_line = ''
        continue
      # asmlinkage long sys_setpriority(int which, int who, int niceval);
      # FIXME: multi-line function!
      m = re.search(r'^asmlinkage\s+(?:long|int)\s+([a-z0-9_]+)\((.*)\);', the_line)
      if m:
        (name, arg_str) = m.groups()
        # parse args
        args = []
        if arg_str:
          if arg_str == "void":
            print("--> void arg for %s" % (name))
          else:
            no_arg_name = False
            for arg in arg_str.split(","):
              mm = re.search(r'^((?:[a-z0-9_ *]+)\s+[*]?)([a-z0-9_]*)$', arg)
              if mm:
                (ctype, arg_name) = mm.groups()
                args.append({'Ctype': ctype, 'Name': arg_name})
                if arg_name == "" and not no_arg_name:
                  print("**> No arg name for %s" % name)
                  no_arg_name = True
        sys_funcs[name] = args

    for number in syscalls:
      if syscalls[number]['EntryPoint'] in sys_funcs: 
        key = syscalls[number]['EntryPoint']
      elif syscalls[number]['Implementation'] in sys_funcs:
        key = syscalls[number]['Implementation']
      else:
        print('Unable to find syscall %d arg info for %s (%s)' % (number, syscalls[number]['EntryPoint'], syscalls[number]['Implementation']))
        continue
      syscalls[number]['Args'] = sys_funcs[key]
    #return syscalls

def parse_type(t):
    if re.search(r'^(const\s*)?char\s*(__user\s*)?\*\s*$', t):
        return "ARG_STR"
    if t.endswith('*'):
        return "ARG_PTR"
    return "ARG_INT"

def write_output(syscalls_h, types, numbers):
    out = open(syscalls_h, 'w')

    print("#define MAX_SYSCALL_NUM %d" % (max(numbers.keys()),), file=out)
    print("struct syscall_entry syscalls[] = {", file=out)
    for num in sorted(numbers.keys()):
        name = numbers[num]
        if name in types:
            args = types[name]
        else:
            args = ["void*"] * 6

        print("  [%d] = {" % (num,), file=out)
        print("    .name  = \"%s\"," % (name,), file=out)
        print("    .nargs = %d," % (len(args,)), file=out)
        out.write(   "    .args  = {")
        out.write(", ".join([parse_type(t) for t in args] + ["-1"] * (6 - len(args))))
        out.write("}},\n");

    print("};", file=out)
    out.close()

def main(args):
    if not args:
        print("Usage: %s /path/to/linux/headers" % (sys.argv[0],), file=sys.stderr)
        return 1
    linux_dir = args[0]
    syscall_file = "syscalls.h"
    if os.uname()[4] == 'x86_64':
        if USE_SYSCALL_TBL:
          sys_num_file = "syscall_64.tbl"
        else:
          sys_num_file = "syscalls_64.h"
    else:
        if USE_SYSCALL_TBL:
          sys_num_file = "syscall_32.tbl"
        else:
          sys_num_file = "syscalls_32.h"
    sys_num_file = os.path.join(linux_dir, sys_num_file)

    print('Analyzing syscall numbers...')
    if USE_SYSCALL_TBL:
      syscall_info = parse_tbl_file(sys_num_file)
    else:
      syscall_info = do_syscall_numbers(sys_num_file)
    # print("syscall numbers: ", syscall_numbers)
    
    print('Analyzing syscall args...')
    find_args(os.path.join(linux_dir, syscall_file), syscall_info)
    #print("syscall numbers: ", syscall_info)
    #write_output('syscallents.h', syscall_types, syscall_numbers)

if __name__ == '__main__':
    # sys.exit(main(sys.argv[1:]))
    sys.exit(main(["kernel"]))
