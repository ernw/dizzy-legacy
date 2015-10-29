#!/usr/bin/env python3

#       tools.py
#       
#       Copyright 2013 Daniel Mende <mail@c0decafe.de>
#

#       Redistribution and use in source and binary forms, with or without
#       modification, are permitted provided that the following conditions are
#       met:
#       
#       * Redistributions of source code must retain the above copyright
#         notice, this list of conditions and the following disclaimer.
#       * Redistributions in binary form must reproduce the above
#         copyright notice, this list of conditions and the following disclaimer
#         in the documentation and/or other materials provided with the
#         distribution.
#       * Neither the name of the  nor the names of its
#         contributors may be used to endorse or promote products derived from
#         this software without specific prior written permission.
#       
#       THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
#       "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
#       LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
#       A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
#       OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
#       SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
#       LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
#       DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
#       THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#       (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#       OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import struct

DEBUG = False

def unique(seq, idfun=None): 
    # order preserving
    if idfun is None:
        def idfun(x): return x
    seen = {}
    result = []
    for item in seq:
        marker = idfun(item)
        if marker in seen: continue
        seen[marker] = 1
        result.append(item)
    return result

def read_with_length(data, length, endian='!'):
    try:
        #fill with zeros until length is correct.
        out = None
        if length <= 8:
            (out,) = struct.unpack("%sB" % endian, data[0])
        elif length <= 16:
            (out,) = struct.unpack("%sH" % endian, data[0:1])
        elif length <= 32:
            (out,) = struct.unpack("%sI" % endian, data[0:3])
        elif length <= 64:
            (out,) = struct.unpack("%sQ" % endian, data[0:7])
        else:
            raise dizz_runtimeException("cant read with len >64")
    except Exception as e:
        if DEBUG:
            print("Can't unpack %s: %s" %(data, str(e)))
        raise e
        
def pack_with_length(data, length, endian='!'):
    try:
        if length <= 8:
            return struct.pack("%sB" % endian, data)
        elif length <= 16:
            return struct.pack("%sH" % endian, data)
        elif length <= 32:
            out = struct.pack("%sI" % endian, data)
        #~ if length < 64:
            #~ return struct.pack("!Q", data)
        else:
            out = b""
            for i in range(0, length, 32):
                if endian == '!' or endian == '<':
                    out = out + struct.pack("%sI" % endian, data & 0xffffffff)
                else:
                    out = struct.pack("%sI" % endian, data & 0xffffffff) + out
                data = data >> 32
        bl = length // 8
        if length % 8 > 0:
            bl += 1
        if endian == '!' or endian == '>':
            return out[-bl:]
        else:
            return out[:bl]
    except Exception as e:
        if DEBUG:
            print("Can't pack %s: %s" %(data, str(e)))
        raise e

def chr_to_bin(c):
    out = ""
    for i in range(0,8):
        if i == 4:
            out += " "
        out += "%d" % (((ord(c) << i) & 0x80) >> 7)
    return out

def str_to_bin(s):
    out = ""
    c = 1
    for i in s:
        out += chr_to_bin(i)
        if c % 8 == 0:
            out += "\n"
        else:
            out += "  "
        c += 1
    return out[:-2]
