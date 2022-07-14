#!/usr/bin/env python3
from pwn import *
elf = context.binary = ELF("./chall")
p = process("./chall")
gdb.attach(p,"init-gef")

def create_string(length, content):

	print(p.recvuntil(b'5. Exit'))
	p.sendline(b'1')
	print(p.recvuntil(b'What type would you like?'))
	p.sendline(b'1')
	print(p.recvuntil(b'like your string to be'))
	p.sendline(str(length))
	print(p.recvuntil(b'data'))
	p.sendline(content)

def edit_char(index, character):
	print(p.recvuntil(b'5. Exit'))
	p.sendline(b'3')
	print(p.recvuntil(b'What index would you like to modify'))
	p.sendline(str(index))
	print(p.recvuntil(b'What type would you like?'))
	p.sendline(b'4')
	print(p.recvuntil(b'What is your value:'))
	p.sendline(character)

def edit_string(index, length, data):
	print(p.recvuntil(b'5. Exit'))
	p.sendline(b'3')

	print(p.recvuntil(b'What index would you like to modify'))
	p.sendline(str(index))

	print(p.recvuntil(b'What type would you like?'))
	p.sendline(b'1')

	print(p.recvuntil(b'like your string to be'))
	p.sendline(str(length))

	print(p.recvuntil(b'data'))
	p.sendline(data)

def display():
	print(p.recvuntil(b'5. Exit\n'))
	p.sendline(b'2')    
p.interactive()