# Writeup of PicoCTF challenge Cache Me Outside

For this write-up I used the work of [Dvd848](https://github.com/Dvd848/CTFs/blob/master/2021_picoCTF/Cache_Me_Outside.md) but I added my own thinking and problem solving ideas to complement the approach already described.

## Problem Description

AUTHOR: MADSTACKS
Description

While being super relevant with my meme references, I wrote a program to see how much you understand heap allocations. 

- `nc mercury.picoctf.net 36605`
- [heapedit](./heapedit) 
- [Makefile](./Makefile)
- [libc.so.6](./libc.so.6)

Hint
- It may be helpful to read a little bit on GLIBC's tcache.

## Initial experimentation

When I connect to the specified server I can supply a memory address, and a byte value and then the program exits.  For example:

```
kali-amd64# nc mercury.picoctf.net 36605
You may edit one byte in the program.
Address: 23
Value: 11
t help you: this is a random string.
```

The supplied binaries are obviously there so I can do local experiments, understand the program and then tackle the actual program accessed over the network.

## Tooling

A few weird things stand out.
- Why do I have a binary, and a C runtime library and a Makefile?
- What is the tcache and why is it relevant?

When running the binary it crashes on a Kali linux box (arm64 architecture, ubuntu distribution based).

```
kali-amd64# ./heapedit
Inconsistency detected by ld.so: dl-call-libc-early-init.c: 37: _dl_call_libc_early_init: Assertion `sym != NULL' failed!
```

I have gdb installed on my Kali box, and also the GEF extension.  This makes it a hacker's GDB by giving you more helpful commands and informational display.

I find that gdb run of the binary fails even before `main` gets reached:

```
kali-amd64# gdb heapedit
GNU gdb (Debian 13.2-1) 13.2
.
.
Type "apropos word" to search for commands related to "word"...
break GEF for linux ready, type `gef' to start, `gef config' to configure
88 commands loaded and 5 functions added for GDB 13.2 in 0.03ms using Python engine 3.11
Reading symbols from heapedit...
(No debugging symbols found in heapedit)
gef➤  break main
Breakpoint 1 at 0x40080b
gef➤  r
Starting program: /home/faisal/Documents/pico-ctf/cache-me-outside/heapedit 
Inconsistency detected by ld.so: dl-call-libc-early-init.c: 37: _dl_call_libc_early_init: Assertion `sym != NULL' failed!
[Inferior 1 (process 379441) exited with code 0177]
```

Looking at the binary it uses its own libc:
```
kali-amd64# ldd heapedit
	linux-vdso.so.1 (0x00007ffd117cd000)
	libc.so.6 => ./libc.so.6 (0x00007fc026400000)
	/lib64/ld-linux-x86-64.so.2 (0x00007fc026973000)
```

and the Makefile also highlights that because it has
` -Xlinker -rpath=./` which indicates it picks up its dynamic libraries from the current directory.

From looking at the write-up of Dvd848 I saw that when you need to do a binary exploitation to should use a tool to make the binary compatible on the system you are currently on.  I therefore installed [pwninit](https://github.com/io12/pwninit).  It requires `openssl-dev` `pkg-config` `patchelf` support packages installed.

Then you can run `$HOME/.cargo/bin/pwninit` and it will notice heapedit and libc.so.6 in your current directory and create patched binary `heapedit_patched`.

When I run it I get:
```
kali-amd64# ./heapedit_patched 
[1]    386364 segmentation fault  ./heapedit_patched
```

This is progress in that it starts, but fails.

Looking for obvious strings we see:
```
kali-amd64# strings heapedit_patched | grep flag
flag.txt
kali-amd64# grep -i pico heapedit_patched 
kali-amd64# 
```

There is a quick way to find out what the binary is doing at a library-call perspective, since that our binary has a custom libc in operation for it.

```
kali-amd64# ltrace -x "@libc.so.6" -o out1.txt ./heapedit_patched 
kali-amd64# cat out1.txt
__libc_start_main@libc.so.6(0x400807, 1, 0x7ffd92273828, 0x400a80 <unfinished ...>
__cxa_atexit@libc.so.6(0x7f2c6ee109f0, 0, 0, 0x400a80 <unfinished ...>
__new_exitfn@libc.so.6(0x7f2c6edeb718, 1, 0, 0x400a80)                                      = 0x7f2c6edecd90
<... __cxa_atexit resumed> )                                                                = 0
_setjmp@libc.so.6(0x7ffd92273770, 0, 0x7f2c6f027760, 0x400a80 <unfinished ...>
__sigsetjmp@libc.so.6(0x7ffd92273770, 0, 0x7f2c6f027760, 0x400a80 <unfinished ...>
__sigjmp_save@libc.so.6(0x7ffd92273770, 0, 0xd1b3afe03b07f9d7, 0x400a80)                    = 0
<... __sigsetjmp resumed> )                                                                 = 0
<... _setjmp resumed> )                                                                     = 0
setbuf(0x7f2c6edec760, 0 <unfinished ...>
setbuf@libc.so.6(0x7f2c6edec760, 0 <unfinished ...>
setbuffer@libc.so.6(0x7f2c6edec760, 0, 8192 <unfinished ...>
_IO_file_setbuf@libc.so.6(0x7f2c6edec760, 0, 0, 2880 <unfinished ...>
_IO_default_setbuf@libc.so.6(0x7f2c6edec760, 0, 0, 2880 <unfinished ...>
_IO_file_sync@libc.so.6(0x7f2c6edec760, 0, 0x7f2c6ede7760, 2880)                            = 0
<... _IO_default_setbuf resumed> )                                                          = 0x7f2c6edec760
<... _IO_file_setbuf resumed> )                                                             = 0x7f2c6edec760
_IO_file_setbuf@libc.so.6(0x7f2c6edec760, 0, 0, 2880 <unfinished ...>
_IO_default_setbuf@libc.so.6(0x7f2c6edec760, 0, 0, 2880 <unfinished ...>
_IO_file_sync@libc.so.6(0x7f2c6edec760, 0, 0x7f2c6ede7760, 2880)                            = 0
<... _IO_default_setbuf resumed> )                                                          = 0x7f2c6edec760
<... _IO_file_setbuf resumed> )                                                             = 0x7f2c6edec760
<... setbuffer resumed> )                                                                   = <void>
<... setbuf resumed> )                                                                      = <void>
<... setbuf resumed> )                                                                      = <void>
fopen("flag.txt", "r" <unfinished ...>
fopen@libc.so.6("flag.txt", "r" <unfinished ...>
malloc@libc.so.6(552 <unfinished ...>
malloc_hook_ini@libc.so.6(552, 0x7f2c6ea7eeba, 0x7f2c6eded8c0, 2880 <unfinished ...>
ptmalloc_init.part.0@libc.so.6(552, 0x7f2c6ea7eeba, 0xffffffff, 2880 <unfinished ...>
_dl_addr@libc.so.6(0x7f2c6ea91730, 0x7ffd922735e0, 0x7ffd922735d0, 0)                       = 1
<... ptmalloc_init.part.0 resumed> )                                                        = 0
tcache_init.part.4@libc.so.6(10, 0x7ffd922735d8, -72, 0 <unfinished ...>
_int_malloc@libc.so.6(0x7f2c6edebc40, 576, -72, 0 <unfinished ...>
sysmalloc@libc.so.6(592, 0x7f2c6edebc40, 0, 0x7f2c6edebca0 <unfinished ...>
__default_morecore@libc.so.6(0x21000, 0x7f2c6edebc40, 0x20270, 0 <unfinished ...>
sbrk@libc.so.6(135168 <unfinished ...>
brk@libc.so.6(0, 0x7f2c6edebc40, 0x20270, 0)                                                = 0
brk@libc.so.6(0x25a1000, 0x7f2c6edebc40, 0x2580000, 0x7f2c6eb165b9)                         = 0
<... sbrk resumed> )                                                                        = 0x2580000
<... __default_morecore resumed> )                                                          = 0x2580000
__default_morecore@libc.so.6(0, 0x25a1000, 0x2580000, 0x21000 <unfinished ...>
sbrk@libc.so.6(0)                                                                           = 0x25a1000
<... __default_morecore resumed> )                                                          = 0x25a1000
<... sysmalloc resumed> )                                                                   = 0x2580010
<... _int_malloc resumed> )                                                                 = 0x2580010
<... tcache_init.part.4 resumed> )                                                          = 0
_int_malloc@libc.so.6(0x7f2c6edebc40, 552, 0, 0x2580010)                                    = 0x2580260
<... malloc_hook_ini resumed> )                                                             = 0x2580260
<... malloc resumed> )                                                                      = 0x2580260
_IO_no_init@libc.so.6(0x2580260, 0, 0, 0x2580350 <unfinished ...>
_IO_old_init@libc.so.6(0x2580260, 0, 0, 0x2580350)                                          = 0x2580340
<... _IO_no_init resumed> )                                                                 = 0x2580340
_IO_new_file_init_internal@libc.so.6(0x2580260, 0xfbad0000, 0, 0x2580350 <unfinished ...>
_IO_link_in@libc.so.6(0x2580260, 0xfbad0000, 0, 0x2580350)                                  = 0
<... _IO_new_file_init_internal resumed> )                                                  = 0
_IO_file_fopen@libc.so.6(0x2580260, 0x400b0a, 0x400b08, 1 <unfinished ...>
open@libc.so.6("flag.txt", 0, 0666)                                                         = -1
<... _IO_file_fopen resumed> )                                                              = 0
_IO_un_link@libc.so.6(0x2580260, 0x400b0a, -128, 0)                                         = 0
free@libc.so.6(0x2580260)                                                                   = <void>
<... fopen resumed> )                                                                       = 0
<... fopen resumed> )                                                                       = 0
fgets( <unfinished ...>
fgets@libc.so.6( <unfinished ...>
--- SIGSEGV (Segmentation fault) ---
+++ killed by SIGSEGV +++
```

This shows that the binary needs "flags.txt" and then reading from the non-existant file crashes the program.  So we shall just create a dummy file containing `hello`.  The program then runs.
