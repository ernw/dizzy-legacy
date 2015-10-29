#!/usr/bin/env python3

#       dizzy.py
#       
#       Copyright 2011 Daniel Mende <mail@c0decafe.de>
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

import binascii
import copy
import ctypes
import fcntl
import io
import math
from optparse import OptionParser
import os
import platform
import pprint
import random
import select
import ssl
import socket
import struct
import subprocess
import sys
import time
import traceback

import tools

if sys.version_info.major < 3:
    print("This script is intended for use with python >= 3!")
    sys.exit(1)

VERSION = "0.8.3"
PLATFORM = platform.system()
DEBUG = False
DEBUG2 = False
DEBUG3 = False

RANDOM_SEED="1l0v3D1zzYc4us31tsR4nd0m1sr3Pr0duc4bl3!"
random.seed(RANDOM_SEED)
#CODEC = "ISO-8859-1"
CODEC = "utf-8"

SCTP_STREAM = 1
SCTP_PPID = 1
SCTP_FLAGS = 0 #MSG_ADDR_OVER ?

interaction_globals = {}

class ifreq(ctypes.Structure):
    _fields_ = [("ifr_ifrn", ctypes.c_char * 16),
                ("ifr_flags", ctypes.c_short)]

#rfc6458 => on linux only draft-ietf-tsvwg-sctpsocket-07.txt
class sctp_sndrcvinfo(ctypes.Structure):
    _fields_ = [("sinfo_stream", ctypes.c_uint16),
                ("sinfo_ssn", ctypes.c_uint16),
                ("sinfo_flags", ctypes.c_uint16),
                ("sinfo_ppid", ctypes.c_uint32),
                ("sinfo_context", ctypes.c_uint32),
                ("sinfo_timetolive", ctypes.c_uint32),
                ("sinfo_tsn", ctypes.c_uint32),
                ("sinfo_cumtsn", ctypes.c_uint32),
                ("sinfo_assoc_id", ctypes.c_int)]

try:
    import usb
    usb_present = True
except Exception as e:
    print(e)
    usb_present = False
    print("No GoodFETMAXUSB libs found. USB support disabled!")
        
class dizz_sessionException(Exception):
    pass

class dizz_session(object):
    IFF_PROMISC = 0x100
    SIOCGIFFLAGS = 0x8913
    SIOCSIFFLAGS = 0x8914
    ETH_P_ALL = 0x0003
    SCTP_SNDRCV = 0x1
    SOL_SCTP = 0x84
    SCTP_DEFAULT_SEND_PARAM = 0xa

    def __init__(self, session_type, interface=None, dest=None,
                dport=None, src='', sport=None, timeout=1, recv_buffer=4096,
                filename=None, cmd=None, auto_reopen=True, client_cert=None,
                client_key=None, server_side=False, connect_retry=3):
        self.session_type = session_type
        self.timeout = timeout
        self.recv_buffer = recv_buffer
        self.is_open = False
        self.auto_reopen = auto_reopen
        self.server_side = server_side
        self.connect_retry = connect_retry
        if server_side:
            if self.session_type == "eth" or self.session_type == "stdout" or self.session_type == "cmd" or self.session_type == "file":
                raise dizz_sessionException("no server side support for session session_type '%s'" % self.session_type)
        if session_type == "eth":
            self.interface = interface
            return
        elif session_type == "udp":
            self.sock = socket.SOCK_DGRAM
        elif session_type == "tcp" or session_type == "tls":
            self.sock = socket.SOCK_STREAM
        elif session_type == "sctp":
            self.sock = socket.SOCK_SEQPACKET
        elif session_type == "stdout" or session_type == "stdout-hex":
            self.maxsize = None
            return
        elif session_type == "cmd":
            self.maxsize = None
            self.cmd = cmd
            return
        elif session_type == "file":
            self.filename = filename
            self.filecount = 0
        elif session_type == "usb-dscr":
            self.filename = filename
            self.fuzz_dscr = dest
        elif session_type == "usb-endp":
            self.filename = filename
        else:
            raise dizz_sessionException("unknown session_type: %s" % session_type)
        if session_type == "udp" or session_type == "tcp" or session_type == "tls" or session_type == "sctp":
            try:
                tmp = socket.inet_aton(dest)
                self.af = socket.AF_INET
            except Exception as e:
                try:
                    tmp = socket.inet_pton(socket.AF_INET6, dest)
                    self.af = socket.AF_INET6
                except Exception as f:
                    raise dizz_sessionException("unknown address family: %s: %s, %s" % (dest, str(e), str(f)))
            if src != '':                
                try:
                    tmp = socket.inet_aton(src)
                except Exception as e:
                    try:
                        tmp = socket.inet_pton(socket.AF_INET6, src)
                    except Exception as f:
                        raise dizz_sessionException("unknown address family: %s: %s, %s" % (src, str(e), str(f)))
                    else:
                        if not self.af == socket.AF_INET6:
                            raise dizz_sessionException("address family missmatch: %s - %s" % (dest, src))
                else:
                    if not self.af == socket.AF_INET:
                        raise dizz_sessionException("address family missmatch: %s - %s" % (dest, src))
        if session_type == "sctp":
            self.sndrcvinfo = sctp_sndrcvinfo()
            self.sndrcvinfo.sinfo_stream = SCTP_STREAM
            self.sndrcvinfo.sinfo_ppid = socket.htonl(SCTP_PPID)
        self.cs = None
        self.dest = dest
        self.src = src
        self.dport = dport
        self.sport = sport
        self.client_cert = client_cert
        self.client_key = client_key
        self.maxsize = 65534
        
    def open(self):
        try:
            if self.session_type == "eth":
                self.s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, self.ETH_P_ALL)
                #set interface
                self.s.bind((self.interface, self.ETH_P_ALL))
                #enable promisc
                #windows:
                #self.s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
                #linux:
                self.ifr = ifreq()
                ifname = ctypes.create_string_buffer(self.interface.encode(CODEC))
                self.ifr.ifr_ifrn = ifname.value
                fcntl.ioctl(self.s.fileno(), self.SIOCGIFFLAGS, self.ifr) # G for Get
                self.ifr.ifr_flags |= self.IFF_PROMISC
                fcntl.ioctl(self.s.fileno(), self.SIOCSIFFLAGS, self.ifr) # S for Set
                self.maxsize = 1500
            elif self.session_type == "file":
                filename = "%s-%i" % (self.filename, self.filecount)
                self.f = open(filename, 'w')
                self.filecount += 1
            elif self.session_type == "stdout" or self.session_type == "stdout-hex":
                self.f = sys.stdout.buffer
            elif self.session_type == "cmd":
                pass
            elif self.session_type == "usb-dscr":
                if not usb_present:
                    raise dizz_sessionException("USB support disabled.")
            elif self.session_type == "usb-endp":
                if usb_present:
                    self.u = usb.dizzyUSB(self.filename, self.timeout)
                    self.u.open(self.dest)
                else:
                    raise dizz_sessionException("USB support disabled.")
            else:
                self.s = socket.socket(self.af, self.sock)
                if self.dest == "255.255.255.255":
                    self.s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self.s.settimeout(self.timeout)
                sendbuf = self.s.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF)
                if sendbuf < self.maxsize:
                    self.maxsize = sendbuf
                if self.session_type == "sctp":
                    self.s.setsockopt(self.SOL_SCTP, self.SCTP_DEFAULT_SEND_PARAM, self.sndrcvinfo)
                if self.sport:
                    self.s.bind((self.src, self.sport))
                if self.session_type == "tls":
                    self.s = ssl.SSLSocket(self.s, self.client_key, self.client_cert, ssl_version=3)
                if self.session_type == "tcp" or self.session_type == "tls":
                    if self.server_side:
                        self.s.listen(1)
                        (self.cs, (rip, rport)) = self.s.accept()
                        if self.dport:
                            while self.dport != rport or self.src != rip:
                                if DEBUG:
                                    if self.dport != rport:
                                        print("remote port %i not destination port %i" % (rport, self.dport))
                                    if self.src != rip:
                                        print("remote ip %s not destination ip %i" % (rip, self.dst))
                                (self.cs, (sip, rport)) = self.s.accept()
                        self.cs.settimeout(self.timeout)
                    else:
                        connected = False
                        attempt = 1
                        try: 
                            self.s.connect((self.dest, self.dport))
                            connected = True
                        except (socket.timeout, ssl.SSLError):
                            print("Connection attempt %d timed out." % (attempt))
                            while not connected and attempt <= self.connect_retry:
                                try:
                                    (r, w, x) = select.select([], [self.s], [], self.timeout)
                                    if self.s in w:
                                        connected = True
                                except: pass
                                attempt += 1
                            if not connected:
                                raise dizz_sessionException("too much connection attempts")
        except Exception as e:
            if DEBUG:
                traceback.print_exc()
            raise dizz_sessionException("cant open session: %s" % str(e))
        else:
            self.is_open = True
    
    def close(self):
        if self.session_type == "eth":            
            self.ifr.ifr_flags &= ~self.IFF_PROMISC
            fcntl.ioctl(self.s.fileno(), self.SIOCSIFFLAGS, self.ifr)
        elif self.session_type == "file":
            self.f.close()
        elif self.session_type == "stdout" or self.session_type == "stdout-hex":
            pass
        elif self.session_type == "cmd":
            pass
        elif self.session_type == "usb-dscr":            
            self.u.close()
        elif self.session_type == "usb-endp":
            self.u.close()
        else:
            self.s.close()
            self.s = None
            if self.cs:
                self.cs.close()
                self.cs = None
        self.is_open = False

    def send(self, data):
        try:
            if not self.maxsize is None and len(data) > self.maxsize:
                data = data[:self.maxsize-1]
                if DEBUG:
                    print("Truncated data to %d byte." % self.maxsize)
            if self.session_type == "eth":
                self.s.send(data)
            elif self.session_type == "file":
                self.f.write(data)
            elif self.session_type == "stdout":
                self.f.write(data + b"\n")
            elif self.session_type == "stdout-hex":
                self.f.write(binascii.hexlify(data))
            elif self.session_type == "cmd":
                try:
                    subprocess.call("%s %s" % (self.cmd, binascii.hexlify(data).upper()), shell=True)
                except Exception as e:
                    raise dizz_sessionException("error on executing %s: '%s'" % (self.cmd, str(e)))
            elif self.session_type == "usb-dscr":                
                self.u = usb.dizzyUSB(self.filename, self.timeout, data=data, fuzz_dscr=self.fuzz_dscr)
                self.u.open()
                self.u.close()
            elif self.session_type == "usb-endp":
                if not self.u.opened:
                    raise dizz_sessionException("usb connection closed...")
                try:
                    self.u.write(data)
                except ValueError as e:
                    raise dizz_sessionException("error sending to endpoint: %s" % str(e))
            elif self.session_type == "tcp" or self.session_type == "tls":
                if self.server_side:
                    if not self.cs:
                        raise dizz_sessionException("no client connection, cant send")
                    self.cs.send(data)
                else:
                    self.s.send(data)
            #~ elif self.session_type == "sctp":
                #~ self.s.sendmsg([data], [(socket.IPPROTO_SCTP, self.SCTP_SNDRCV, self.sndrcvinfo)], 0, (self.dest, self.dport))
            else:
                self.s.sendto(data, (self.dest, self.dport))
        except Exception as e:
            if self.auto_reopen:
                if DEBUG:
                    print("session got closed '%s', autoreopening..." % str(e))
                    traceback.print_exc()
                self.close()
                self.open()
            else:
                self.close()
                raise dizz_sessionException("error on sending '%s', connection closed." % str(e))
    
    def recv(self):
        if self.session_type == "eth":
            return self.s.recv(2048)
        elif self.session_type == "file":
            return None
        elif self.session_type == "cmd":
            return None
        elif self.session_type == "usb":
            if not self.u.opened:
                raise dizz_sessionException("usb connection closed...")
            return self.u.read()
        elif self.session_type == "stdout" or self.session_type == "stdout-hex":
            line = sys.stdin.readline()
            if line == ".\n":
                return None
            else:
                return line
        else:
            if self.server_side:
                return self.cs.recv(self.recv_buffer)
            else:
                return self.s.recv(self.recv_buffer)

class dizz_library(object):
    def __init__(self):
        self.lib = {}
        self.load_strings("lib/std_string_lib.txt")

    def get_next(self, obj):
        libidx = obj["length"]
        if libidx is None:
            if not obj["encoding"] is None:
                cur = obj["cur"].decode(obj["encoding"])
            else:
                cur = obj["cur"].decode(CODEC)
        else:
            cur = obj["cur"]
        if obj["_type"] == "list":
            libidx = obj["listname"]
        if not libidx in self.lib:
            self.gen_entries(libidx)
        if cur not in self.lib[libidx]:
            if libidx == None:
                return self.lib[libidx][0]
            return None
        return self.lib[libidx][self.lib[libidx].index(cur) + 1]

    def gen_entries(self, length):
        bytelen = length // 8
        if length % 8 > 0:
            bytelen += 1
        if length >= 4:
            entr = []
            entr += [tools.pack_with_length(0, length)]
            entr += [tools.pack_with_length(1, length)]
            entr += [tools.pack_with_length(2, length)]
            entr += [tools.pack_with_length(3, length)]
            entr += [tools.pack_with_length(4, length)]
            if length > 8:
                entr += [tools.pack_with_length(1, length, endian="<")]
                entr += [tools.pack_with_length(2, length, endian="<")]
                entr += [tools.pack_with_length(3, length, endian="<")]
                entr += [tools.pack_with_length(4, length, endian="<")]
            max = int(math.pow(2, length)) - 1
            if length > 8:
                entr += [tools.pack_with_length(max - 4, length, endian="<")]
                entr += [tools.pack_with_length(max - 3, length, endian="<")]
                entr += [tools.pack_with_length(max - 2, length, endian="<")]
                entr += [tools.pack_with_length(max - 1, length, endian="<")]
            entr += [tools.pack_with_length(max - 4, length)]
            entr += [tools.pack_with_length(max - 3, length)]
            entr += [tools.pack_with_length(max - 2, length)]
            entr += [tools.pack_with_length(max - 1, length)]
            entr += [tools.pack_with_length(max, length)]
            entr += [None]
        elif length == 3:
            entr = ["\x00", "\x01", "\x02", "\x03", "\x04", "\x05", "\x06", "\x07", None]
        elif length == 2:
            entr = ["\x00", "\x01", "\x02", "\x03", None]
        elif length == 1:
            entr = ["\x00", "\x01", None]
        self.lib[length] = tools.unique(entr)

    def load_strings(self, filename, listname=None, ascii=True):
        if listname in self.lib:
            return
        self.lib[listname] = [ "", None ]
        with open(filename, 'r') as f:
            for l in f:
                if l.rstrip('\n') in self.lib[listname]:
                    pass
                if ascii:
                    self.lib[listname].insert(-1, l.rstrip('\n'))
                else:
                    self.lib[listname].insert(-1, bytes(l.rstrip('\n'), CODEC).decode("unicode_escape").encode(CODEC))
    
class dizz_parseException(Exception):
    pass

class dizz_runtimeException(Exception):
    pass

class dizz(object):
    def __init__(self, library=None):
        self.objects = []
        self.obj_dict = {}
        self.functions = []
        self.cur_obj = None
        self.last_obj = None
        self.null_obj = False
        if not library:
            library = dizz_library()
        self.library = library
        self.filename = None
        
    def update_obj_dict(self):
        self.obj_dict = {}
        for i in self.objects:
            self.obj_dict[i["_name"]] = i

    def load(self, filename):
        self.filename = filename
        ns = {  "field"         :   self.basic_dizz,
                "list"          :   self.list_dizz,
                "rand"          :   self.rand_dizz,
                "link"          :   self.link_dizz,
                "fill"          :   self.fill_dizz,
                "padding"       :   self.padding_dizz,
                "grow"          :   self.grow_dizz,
                
                "none"          :   "none",
                "std"           :   "std",
                "full"          :   "full",
                
                "run_cmd"       :   self.run_cmd,
                "time"          :   self.basic_time,
                "time_no_fracs" :   self.basic_time_no_fracs,
                "length"        :   self.basic_length,
                "ascii_length"  :   self.ascii_length,
                "lambda_length" :   self.lambda_length,
                "csum"          :   self.basic_csum,
                "lambda_csum"   :   self.lambda_csum,
                "lambda2_csum"  :   self.lambda2_csum,
                }
        with open(filename) as f:
            exec(compile(f.read(), filename, 'exec'), ns)
        self.name = ns["name"]
        self.objects = ns["objects"]
        self.functions = ns["functions"]
        self.update_obj_dict()

    def save(self, filename):
        pp = pprint.PrettyPrinter(indent=4)
        with io.open(filename, 'w', encoding=CODEC) as f:
            f.write("#%s %s autogenerated\n" % (self.__class__.__name__, VERSION))
            f.write("name = \"%s\"\n\n" % self.name)
            class ndict(dict):
                def __repr__(self):
                    if self["_type"] == "basic":
                        if self["length"] == None:
                            return "field('%s', None, %s, '%s')" % (self["_name"], self["default"].encode("unicode_escape"), self["fuzz"])
                        else:
                            return "field('%s', %d, %s, '%s')" % (self["_name"], self["length"], self["default"].encode("unicode_escape"), self["fuzz"])
                    elif self["_type"] == "list":
                        return "list('%s', %s, '%s')" % (self["_name"], self["default"].encode("unicode_escape"), self["listname"])
                    elif self["_type"] == "rand":
                        return "rand('%s', %d)" % (self["_name"], self["length"])
                    elif self["_type"] == "link":
                        return "link('%s', '%s')" % (self["_name"], self["source"])
                    elif self["_type"] == "padding":
                        return "padding('%s', '%s', '%s', %d, %s)" % (self["_name"], self["start"], self["end"], self["modulo"], self["default"].encode("unicode_escape"))
            tmpobj = []
            for i in self.objects:
                n = ndict(i)
                tmpobj += [ n ]
            f.write("objects = %s\n\n" % pp.pformat(tmpobj))
            class ndict(dict):
                def __repr__(self):
                    if self["func"] == "length":
                        return "length('%s', '%s', '%s')" % (self["dest"], self["start"], self["end"])
                    if self["func"] == "ascii_length":
                        return "ascii_length('%s', '%s', '%s')" % (self["dest"], self["start"], self["end"])
                    elif self["func"] == "csum":
                        return "csum('%s', '%s', '%s', '%s')" % (self["dest"], self["start"], self["end"], self["type"])
                    elif self["func"] == "time":
                        if self["flavour"] == "no_fracs":
                            return "time_no_fracs('%s', %d)" % (self["dest"], self["offset"])
                        else:
                            return "time('%s', %d)" % (self["dest"], self["offset"])
            tmpobj = []
            for i in self.functions:
                n = ndict(i)
                tmpobj += [ n ]
            f.write("functions = %s\n" % pp.pformat(tmpobj))

    def _alignmod(self, obj, mod):
        _DEBUG = DEBUG3
        out = b""
        if _DEBUG: print("cur: %s" % binascii.hexlify(obj["cur"]))
        out += bytes([(obj["cur"][0] << 8 - mod) & 0xff])
        if _DEBUG: print("out: %s" % binascii.hexlify(out))
        for j in range(1, obj["bytelen"]):
            #~ if DEBUG:
                #~ print("out %s       obj[\"cur\"] %s" % (type(out), type(obj["cur"])))
                #~ print("out[-1:] %s %s" % (type(out[-1:]), out[-1:]))
                #~ print("obj[\"cur\"][j] %s %s" % (type(obj["cur"][j]), obj["cur"][j]))
                #~ print("out[-1:] %s       out[-1] %s" % (out[-1:], out[-1]))
            if _DEBUG: print("j: %d" % j)
            tmp = out[-1] | (obj["cur"][j] >> mod) 
            if _DEBUG: print("tmp: %x" % tmp)
            out = out[:-1] + bytes([tmp])
            if _DEBUG: print("out: %s" % binascii.hexlify(out))
            tmp2 = (obj["cur"][j] << 8 - mod) & 0xff
            if _DEBUG: print("tmp2: %x" % tmp2)
            out += bytes([tmp2])
            if _DEBUG: print("out: %s" % binascii.hexlify(out))
        return out

    def generate(self, offset=0, leading_data=b"\x00"):
        if len(self.objects) == 0:
            return b""
        return self._get_obj_data(0, len(self.objects) - 1, offset, leading_data)

    def _nullobj(self, obj):
        if obj["fuzz"] == "none":
            return
        if obj["bytelen"]:
            obj["cur"] = bytes([ 0x00 for i in range(obj["bytelen"]) ])
        else:
            obj["cur"] = b""

    def _nextobj(self, reset=True, null=True):
        if reset:
            self.objects[self.cur_obj]["cur"] = self.objects[self.cur_obj]["default"]
        self.cur_obj += 1
        if self.cur_obj < len(self.objects):
            if null:
                self._nullobj(self.objects[self.cur_obj])
        else:
            return False
        return True
        
    def _get_obj_length(self, start, end):
        if isinstance(start, int):
            start_index = start
        elif isinstance(start, str):
            start_index = self.objects.index(self.obj_dict[start])
        else:
            raise dizz_runtimeException("start marker is not string, nor int, but '%s'!" % type(start))
        if isinstance(end, int):
            end_index = end
        elif isinstance(end, str):
            end_index = self.objects.index(self.obj_dict[end])
        else:
            raise dizz_runtimeException("end marker is not string, nor int, but '%s'!" % type(end))
        length = 0
        for i in range(start_index, end_index + 1):
            if not self.objects[i]["length"] is None:
                length += self.objects[i]["length"]
            else:
                length += len(self.objects[i]["cur"]) * 8
        return length
    
    def _get_obj_data(self, start, end, offset=0, leading_data=b"\x00"):
        _DEBUG = DEBUG2
        if isinstance(start, int):
            start_index = start
        elif isinstance(start, str):
            start_index = self.objects.index(self.obj_dict[start])
        else:
            raise dizz_runtimeException("start marker is not string, nor int, but '%s'!" % type(start))
        if isinstance(end, int):
            end_index = end
        elif isinstance(end, str):
            end_index = self.objects.index(self.obj_dict[end])
        else:
            raise dizz_runtimeException("end marker is not string, nor int, but '%s'!" % type(end))
        if offset == 0:
            out = b""
        else:
            out = leading_data
        for i in range(start_index, end_index + 1):
            i = self.objects[i]
            if DEBUG:
                print("name: " + i["_name"])
                print("cur:  " + str(type(i["cur"])))
            if _DEBUG: print("offset: %d" % offset) 
            if i["length"] is None:
                bytelen = len(i["cur"])
                length = bytelen * 8
            else:
                length = i["length"]
                bytelen = i["bytelen"]
            modulo = length % 8
            if _DEBUG: print("modulo: %d" % modulo)
            if offset != 0:
                if modulo != 0:
                    cur = self._alignmod(i, modulo)
                else:
                    cur = i["cur"]
                if _DEBUG: print("cur: %s" % binascii.hexlify(cur))
                for j in range(bytelen):
                    if _DEBUG: print("j: %d" % j)
                    tmp2 = bytes([out[-1] | (cur[j] >> 8 - offset)])
                    if _DEBUG: print("tmp2: %s" % tmp2)
                    out = out[:-1] + tmp2
                    if _DEBUG: print("out: %s" % out)
                    tmp = bytes([(cur[j] << offset) & 0xff])
                    if _DEBUG: print("tmp: %s" % binascii.hexlify(tmp))
                    if j == bytelen - 1:
                        if offset - modulo == 0:
                            if _DEBUG:
                                print("breaking byte aligned")
                            break
                        if modulo - offset > 0:
                            if _DEBUG:
                                print("breaking out of obj data")
                            break
                    out += tmp
                offset = abs(offset - modulo)
            else:
                if modulo != 0:
                    out += self._alignmod(i, modulo)
                    offset = 8 - modulo
                else:
                    out += i["cur"]
            if _DEBUG:
                print(binascii.hexlify(out))
        return out
    
    def _find_first_obj(self):
        self.cur_obj = 0
        while self.objects[self.cur_obj]["fuzz"] == "none":
            self.cur_obj += 1
            if self.cur_obj >= len(self.objects):
                self.cur_obj = None
                return False
        return True
    
    def get_current(self, recurse=False):
        if self.cur_obj is None:
            return None
        if self.last_obj is None and recurse:
            recurse = False
        obj = self.objects[self.cur_obj]
        if recurse:
            obj2 = self.objects[self.last_obj]
            return "%s-%s: %s-%s" % (obj["_name"], obj2["_name"], obj["cur"][:1024], obj2["cur"][:1024])
        else:
            return "%s: %s" % (obj["_name"], obj["cur"][:1024])
    
    def mutate(self, recurse):
        _DEBUG = DEBUG2
        done = False
        if len(self.objects) == 0:
            return False
        while not done:
            if _DEBUG:
                print("cur_obj: %s last_obj: %s null_obj: %s" % (self.cur_obj, self.last_obj, self.null_obj))
            if self.cur_obj == None:
                if not self._find_first_obj():
                    return False
                    #raise dizz_runtimeException("No mutable object found!")
                self._nullobj(self.objects[self.cur_obj])
                break
            if self.cur_obj >= len(self.objects):
                if _DEBUG: print("EOMutate: %d %d" % (self.cur_obj, len(self.objects)))
                self.cur_obj = None
                return False
            else:
                if self.null_obj:
                    while self.cur_obj != self.null_obj:
                        if self.objects[self.cur_obj]["fuzz"] != "none":
                            if _DEBUG:
                                print("NULLing %i" % self.cur_obj)
                            self._nullobj(self.objects[self.cur_obj])
                        self._nextobj(False, False)
                    self._find_first_obj()
                    self.null_obj = False
                obj = self.objects[self.cur_obj]
                if obj["fuzz"] == "none":
                    if recurse:
                        if self.cur_obj == self.last_obj or self.last_obj is None:
                            if self._nextobj(False, True):
                                self.last_obj = self.cur_obj
                                if _DEBUG: print("setting last_obj to %s" % self.cur_obj)
                        else:
                            self._nextobj(False, False)
                    else:
                        self._nextobj()
                elif obj["fuzz"] == "full":
                    if _DEBUG:
                        print("%s: cur: %s, int(cur): %d, max: %d" % (obj["_name"], binascii.hexlify(obj["cur"]), int(binascii.hexlify(obj["cur"]), 16), int(math.pow(2, obj["length"])) - 1))
                    
                    if int(binascii.hexlify(obj["cur"]), 16) >= math.pow(2, obj["length"]) - 1:
                        if recurse:
                            if self.cur_obj == self.last_obj or self.last_obj is None:
                                if self._nextobj(False, True):
                                    self.last_obj = self.cur_obj
                                    if _DEBUG: print("setting last_obj to %s" % self.cur_obj)
                                self.null_obj = self.cur_obj
                                done = True
                            else:
                                self._nextobj(False, False)
                        else:
                            self._nextobj()
                            done = True
                    else:
                        #obj["cur"] = pack_with_length(long(obj["cur"].encode("hex"), 16) + 1, obj["length"], obj["endian"])
                        obj["cur"] = tools.pack_with_length(int(binascii.hexlify(obj["cur"]), 16) + 1, obj["length"])
                        if recurse:
                            self.null_obj = self.cur_obj
                        done = True
                elif obj["fuzz"] == "std":
                    nextval = self.library.get_next(obj)
                    if _DEBUG: print("%s: len: %s cur: %s next: %s" % (obj["_name"], obj["length"], obj["cur"], nextval))
                    if nextval is None:
                        if recurse:
                            if self.cur_obj == self.last_obj or self.last_obj is None:
                                if self._nextobj(False, True):
                                    if _DEBUG: print("setting last_obj to %s" % self.cur_obj)
                                    self.last_obj = self.cur_obj
                                self.null_obj = self.cur_obj
                                done = True
                            else:
                                self._nextobj(False, False)
                        else:
                            self._nextobj()
                            done = True
                    else:
                        if obj["length"] is None:
                            if not obj["encoding"] is None:
                                nextval = nextval.encode(obj["encoding"])
                            else:
                                nextval = nextval.encode(CODEC)                        
                        #if obj["endian"] == "<":
                        #    next = pack_with_length(next, obj["length"], obj["endian"])
                        obj["cur"] = nextval
                        if recurse:
                            self.null_obj = self.cur_obj
                        done = True
                else:
                    raise dizz_runtimeException("unknown fuzzing type: %s" % obj["fuzz"])
        
        if _DEBUG:
            print("cur_obj: %s last_obj: %s null_obj: %s" % (self.cur_obj, self.last_obj, self.null_obj))
        if self.cur_obj >= len(self.objects):
            if _DEBUG: print("EOMutate: %d %d" % (self.cur_obj, len(self.objects)))
            self.cur_obj = None
            return False
        if recurse:
            self._find_first_obj()
        return True

    def operate(self):
        _DEBUG = DEBUG2
        for i in self.objects:
            if i["_type"] == "rand":
                new_rand = [ random.randint(0x00, 0xff) for j in range(i["bytelen"]) ]
                i["cur"] = bytes(new_rand)
            elif i["_type"] == "link":
                i["cur"] = self.obj_dict[i["source"]]["cur"]
            elif i["_type"] == "fill":
                if len(self.obj_dict[i["source"]]["cur"]) % i["fillto"] != 0:
                    i["cur"] = i["fillwith"] * (i["fillto"] - (len(self.obj_dict[i["source"]]["cur"]) % i["fillto"]))
            elif i["_type"] == "padding":
                length = self._get_obj_length(i["start"], i["end"])
                mod = length % i["modulo"]
                if mod != 0:
                    i["length"] = i["modulo"] - mod
                    i["bytelen"] = i["length"] // 8
                    if i["length"] % 8 > 0:
                        i["bytelen"] += 1
                    i["cur"] = i["default"] * i["bytelen"]
                else:
                    i["length"] = 0
                    i["bytelen"] = 0
                    i["cur"] = b""
            elif i["_type"] == "grow":
                index = self.objects.index(self.obj_dict[i["_name"]])
                if index == self.cur_obj:
                    print("deb1") 
                    if i["length"] < i["maxlen"]:
                        i["length"] = i["length"] + 1
                        i["bytelen"] = i["length"] // 8
                        if i["length"] % 8 > 0:
                            i["bytelen"] += 1
                        times = (i["bytelen"] - len(i["default"])) // len(i["fill"])
                        i["cur"] = i["default"] + i["fill"] * times
                    else:
                        i["length"] = i["orglen"]
                        i["cur"] = i["default"]
        for i in self.functions:
            if i["func"] == "length":
                len_index = self.objects.index(self.obj_dict[i["dest"]])
                if len_index != self.cur_obj and len_index != self.last_obj:
                    start_index = self.objects.index(self.obj_dict[i["start"]])
                    end_index = self.objects.index(self.obj_dict[i["end"]])
                    length = 0
                    for j in range(start_index, end_index + 1):
                        if not self.objects[j]["length"] is None:
                            length += self.objects[j]["length"]
                        else:
                            length += len(self.objects[j]["cur"]) * 8
                    length = length // 8
                    if "lambda" in i:
                        length = i["lambda"](length)
                    if i["flavour"] == "ascii":
                        try:
                            self.objects[len_index]["cur"] = bytes(str(length).encode(CODEC))
                        except:
                            if DEBUG:
                                print("Can't update ascii_length, zeroing...")
                            self.objects[len_index]["cur"] = bytes("0".encode(CODEC))
                    else:
                        try:
                            self.objects[len_index]["cur"] = tools.pack_with_length(length, self.objects[len_index]["length"], i["endian"])
                        except:
                            if DEBUG:
                                print("Can't update length, maxing out...")
                            self.objects[len_index]["cur"] = tools.pack_with_length(int(math.pow(2, self.objects[len_index]["length"])) - 1, self.objects[len_index]["length"])
                    if _DEBUG:
                        print("LENGTH: dest: %s, start: %s, end: %s, len: %d" % (i["dest"], i["start"], i["end"], length))
            elif i["func"] == "csum":
                sum_index = self.objects.index(self.obj_dict[i["dest"]])
                if sum_index != self.cur_obj:
                    self.objects[sum_index]["cur"] = self.objects[sum_index]["default"]
                    inp = self._get_obj_data(i["start"], i["end"])
                    if "lambda_in" in i:
                        inp = i["lambda_in"](self, inp)
                    if i["type"] == "custom":
                        output = i["callback"](inp)
                    else:
                        output = self.CHECKSUM[i["type"]]["call"](inp)
                    if "lambda_out" in i:
                        output = i["lambda_out"](self, output)
                    self.objects[sum_index]["cur"] = output
            elif i["func"] == "time":
                time_index = self.objects.index(self.obj_dict[i["dest"]])
                if time_index != self.cur_obj:
                    now = time.time() + i["offset"]
                    secs = int(now)
                    if i["flavour"] == "no_fracs":
                        self.objects[time_index]["cur"] = tools.pack_with_length(secs, 64)
                    else:
                        fracs = int((now - secs) * 65536)
                        self.objects[time_index]["cur"] = tools.pack_with_length(secs, 48) + tools.pack_with_length(fracs, 18)
            elif i["func"] == "run_cmd":
                try:
                    if DEBUG:
                        print("running '%s'" % i["cmd"])
                    subprocess.call(i["cmd"], shell=True)
                except Exception as e:
                    raise dizz_sessionException("error on executing %s: '%s'" % (self.cmd, str(e)))

######### OBJECTS ##########

    def basic_dizz(self, name, length, default, fuzz, endian='!', encoding=None):
        if not name:
            raise dizz_parseException("no name defined!")
        if not isinstance(length, int) and not length is None:
            raise dizz_parseException("length must be int or None")
        if isinstance(length, int) and length == 0:
            raise dizz_parseException("length 0 objects are not allowed!")
        if isinstance(length, int):
            bytelen = length // 8
            if length % 8 != 0:
                bytelen += 1
            if len(default) != bytelen:
                raise dizz_parseException("length of default value doesnt match length attribute: %s" % name)
        else:
            bytelen = None
        if length is None and fuzz == "full":
            raise dizz_parseException("cannot make dizz without length full fuzzable: %s" % name)
        if isinstance(length, int) and length > sys.maxsize and fuzz == "full":
            raise dizz_parseException("cannot make dizz with length '%d' full fuzzable, this would take ages: %s" % (length, name))
        if name in self.obj_dict:
            raise dizz_parseException("dizz with name '%s' already exists!" % name)
        if endian != '<' and endian != '>' and endian != '!':
            raise dizz_parseException("invalid endianness '%s': %s" % (endian, name))
        if endian != '!' and  isinstance(length, int) and length % 16 > 0:
            raise dizz_parseException("endianness can only be set for fields with (len = 16 * n): %s" % name)
        if isinstance(default, str):
            cur = bytes(default.encode(CODEC))
        else:
            cur = bytes(default)
        obj  = {    "_type"     :   "basic",
                    "_name"     :   name,
                    "length"    :   length,
                    "default"   :   cur,
                    "fuzz"      :   fuzz,
                    "endian"    :   endian,
                    "encoding"  :   encoding,

                    "bytelen"   :   bytelen,
                    "cur"       :   cur
                    }
        self.obj_dict[name] = obj
        return obj

    def fill_dizz(self, name, source, fillto, fillwith):
        if source not in self.obj_dict:
            raise dizz_parseException("cannot find source dizz %s" % source)
        if not (self.obj_dict[source]["length"] is None):
            raise dizz_parseException("cannot create fill dizz for source with len!=None: %s" % name)
        dflt = ''
        if len(self.obj_dict[source]["cur"]) % fillto != 0:
            dflt = fillwith * (fillto - (len(self.obj_dict[source]["cur"]) % fillto))
        obj = self.basic_dizz(name, None, dflt, "none")
        obj["_type"] = "fill"
        obj["source"] = source
        obj["fillto"] = fillto
        obj["fillwith"] = fillwith
        return obj

    def list_dizz(self, name, default, listname, ascii=True):
        obj = self.basic_dizz(name, None, default, "std")
        obj["_type"] = "list"
        obj["listname"] = listname
        self.library.load_strings(listname, listname, ascii=ascii)
        return obj
        
    def link_dizz(self, name, source):
        if source not in self.obj_dict:
            raise dizz_parseException("cannot find source dizz %s" % source)
        obj = self.basic_dizz(name, self.obj_dict[source]["length"], self.obj_dict[source]["default"], "none")
        obj["_type"] = "link"
        obj["source"] = source
        return obj
    
    def rand_dizz(self, name, length, encoding=None):
        if not length:
            raise dizz_parseException("cannot create random dizz without length: %s" % name)
        bytelen = length // 8
        if length % 8 != 0:
            bytelen += 1
        obj = self.basic_dizz(name, length, "\x00" * bytelen, "none", encoding=encoding)
        obj["_type"] = "rand"
        return obj
    
    def padding_dizz(self, name, start, end, modulo, value):
        if start not in self.obj_dict:
            raise dizz_parseException("start field '%s' unknown!" % start)
        if end not in self.obj_dict:
            raise dizz_parseException("end field '%s' unknown!" % end)
        obj = self.basic_dizz(name, None, value, "none")
        obj["_type"] = "padding"
        obj["start"] = start
        obj["end"] = end
        obj["modulo"] = modulo
        return obj
    
    def grow_dizz(self, name, length, default, fuzz, fill, maxlen, endian='!', encoding=None):
        obj = self.basic_dizz(name, length, default, fuzz, endian, encoding)
        obj["_type"] = "grow"
        obj["orglen"] = length
        obj["fill"] = fill
        obj["maxlen"] = maxlen
        return obj
    
######### FUNCTIONS ##########
    
    def run_cmd(self, cmd):
        return {    "func"  :   "run_cmd",
                    "cmd"   :   cmd
                    }
    
    def basic_time(self, dest, offset=0):
        if dest not in self.obj_dict:
            raise dizz_parseException("destination field '%s' unknown!" % dest)
        if self.obj_dict[dest]["length"] != 64:
            raise dizz_parseException("destination of time '%s' got len != 64!" % dest)
        if not isinstance(offset, int) and not isinstance(offset, float):
            raise dizz_parseException("offset must be of type int or float!")
        return {    "func"      :   "time",
                    "dest"      :   dest,
                    "offset"    :   offset,
                    "flavour"   :  "default"
                    }

    def basic_time_no_fracs(self, dest, offset=0):
        func = self.basic_time(dest, offset)
        func["flavour"] = "no_fracs"
        return func

    def basic_length(self, dest, start, end, endian="!"):
        if dest not in self.obj_dict:
            raise dizz_parseException("destination field '%s' unknown!" % dest)
        if start not in self.obj_dict:
            raise dizz_parseException("start field '%s' unknown!" % start)
        if end not in self.obj_dict:
            raise dizz_parseException("end field '%s' unknown!" % end)
        if endian != '<' and endian != '>' and endian != '!':
            raise dizz_parseException("invalid endianness '%s': %s" % endian)
        return {    "func"      :   "length",
                    "dest"      :   dest,
                    "start"     :   start,
                    "end"       :   end,
                    "endian"    :   endian,
                    "flavour"   :   "default"
                    }

    def ascii_length(self, dest, start, end, endian="!"):
        func = self.basic_length(dest, start, end, endian)
        func["flavour"] = "ascii"
        return func

    def lambda_length(self, dest, start, end, lamb, endian="!"):
        func = self.basic_length(dest, start, end, endian)
        func["lambda"] = lamb
        return func
    
    def basic_csum(self, dest, start, end, cstype, callback=None):
        if dest not in self.obj_dict:
            raise dizz_parseException("destination field '%s' unknown!" % dest)
        if start not in self.obj_dict:
            raise dizz_parseException("start field '%s' unknown!" % start)
        if end not in self.obj_dict:
            raise dizz_parseException("end field '%s' unknown!" % end)
        if cstype == "custom":
            if callback is None:
               raise dizz_parseException("no callback for custom checksum defined!") 
        else:
            if cstype not in self.CHECKSUM:
                raise dizz_parseException("unknown checksum '%s'!" % cstype)
            if self.CHECKSUM[cstype]["length"] != self.obj_dict[dest]["length"]:
                raise dizz_parseException("length of destination field doesnt match checksum length: %i != %i" % (self.CHECKSUM[cstype]["length"], self.obj_dict[dest]["length"]))
        return {    "func"      :   "csum",
                    "dest"      :   dest,
                    "start"     :   start,
                    "end"       :   end,
                    "type"      :   cstype,
                    "callback"  :   callback,
                    }
    
    def lambda_csum(self, dest, start, end, cstype, lamb):
        func = self.basic_csum(dest, start, end, cstype)
        func["lambda_out"] = lamb
        return func
    
    def lambda2_csum(self, dest, start, end, cstype, lambin, lambout):
        func = self.basic_csum(dest, start, end, cstype)
        func["lambda_in"] = lambin
        func["lambda_out"] = lambout
        return func
    
    def csum_inet(data, csum=0):
        for i in range(0,len(data),2):
            if i + 1 >= len(data):
                csum += data[i] & 0xFF
            else:
                w = ((data[i] << 8) & 0xFF00) + (data[i+1] & 0xFF)
                csum += w
        while (csum >> 16) > 0:
            csum = (csum & 0xFFFF) + (csum >> 16)
        csum = ~csum
        return struct.pack("!H", csum & 0xFFFF)

    CHECKSUM = {    "inet"      :   {   "length" :   16,
                                        "call"   :   csum_inet
                                        },
                    "none"      :   {   "length" :   None,
                                        "call"   :   lambda x: x
                                        }
                    #"custom" is reserved
                    }

class interact_parseException(Exception):
    pass

class interaction(object):
    def __init__(self, library=None, cur_obj=0):
        self.objects = []
        self.functions = []
        if not library:
            library = dizz_library()
        self.library = library
        self.cur_obj = cur_obj
        self.gen_obj = 0

    def load(self, filename):
        self.filename = filename
        global interaction_globals
        ns = {  "dizz"  :   self.dizz_obj,
                "null_dizz"  :   self.null_dizz_obj,
                "copy"  :   self.basic_copy,
                "adv_copy"  :   self.adv_copy,
                "print_dizz":   self.print_dizz,
                "print_field"   :   self.print_field,
                "global"    :   interaction_globals,
                }
        with open(filename) as f:
            exec(compile(f.read(), filename, 'exec'), ns)
        self.name = ns["name"]
        self.objects = ns["objects"]
        self.functions = ns["functions"]

    def save(self, filename):        
        pp = pprint.PrettyPrinter(indent=4)
        with open(filename, 'w') as f:
            f.write("#%s %s autogenerated\n" % (self.__class__.__name__, VERSION))
            f.write("name = \"%s\"\n\n" % self.name)
            class ndict(dict):
                def __repr__(self):
                    if self["type"] == "null_dizz":
                        return "null_dizz()"
                    else:
                        return "dizz('%s', '%s')" % (self["name"], self["dizz"].filename)
            tmpobj = []
            for i in self.objects:
                n = ndict(i)
                tmpobj += [ n ]
            f.write("objects = %s\n\n" % pp.pformat(tmpobj))
            class ndict(dict):
                def __repr__(self):
                    if self["func"] == "copy":
                        return "copy(%d, '%s', %d, %d)" % (self["step"], self["dest"], self["start"], self["end"])
                    elif self["func"] == "adv_copy":
                        return "adv_copy(%d, '%s')" % (self["step"], self["callback"].__name__)
                    elif self["func"] == "print_dizz":
                        return "print_dizz(%d)" % self["step"]
                    elif self["func"] == "print_field":
                        return "print_field(%d, '%s')" % (self["step"], self["field"])
            tmpobj = []
            for i in self.functions:
                n = ndict(i)
                tmpobj += [ n ]
            f.write("funktions = %s\n" % pp.pformat(tmpobj))

    def dizz_obj(self, name, filename, readlen=None):
        if not name:
            raise interact_parseException("no name defined!")

        obj = {}
        obj["type"] = "dizz"
        obj["name"] = name
        obj["dizz"] = dizz(self.library)
        obj["dizz"].load(filename)
        obj["dizz"].operate()
        obj["readlen"] = readlen
        return obj

    def null_dizz_obj(self, name, readlen=None):
        if not name:
            raise interact_parseException("no name defined!")

        obj = {}
        obj["type"] = "null_dizz"
        obj["name"] = name
        obj["dizz"] = dizz(self.library)
        obj["readlen"] = readlen
        return obj        

    def _next_obj(self):
        if self.cur_obj + 1 < len(self.objects):
            self.cur_obj += 1
            return True
        return False
    
    def get_current(self, recurse=False):
        if self.cur_obj == self.gen_obj:
            return "%s: %s" % (self.objects[self.gen_obj]["name"], self.objects[self.gen_obj]["dizz"].get_current(recurse))
        return None

    def generate(self, recurse, test=False):
        _DEBUG = DEBUG2
        ret = b""
        rlen = None
        done = False

        if _DEBUG:
            print("cur: %d\tgen: %d" % (self.cur_obj, self.gen_obj))

        if self.gen_obj < self.cur_obj:
            self.objects[self.gen_obj]["dizz"].operate()
            ret = self.objects[self.gen_obj]["dizz"].generate()
            rlen = self.objects[self.gen_obj]["readlen"]
            self.gen_obj += 1
        else:
            if not test:
                more = self.objects[self.cur_obj]["dizz"].mutate(recurse)
            else:
                more = False
            if not more:
                self.objects[self.cur_obj]["dizz"].operate()
                ret = self.objects[self.cur_obj]["dizz"].generate()
                rlen = self.objects[self.cur_obj]["readlen"]
                if not self._next_obj():
                    if _DEBUG:
                        print("EOInteract")
                    done = True
            else:
                self.gen_obj = 0
                self.objects[self.cur_obj]["dizz"].operate()
                ret = self.objects[self.cur_obj]["dizz"].generate()
                rlen = self.objects[self.cur_obj]["readlen"]
        return (ret, rlen, done)

    def operate(self, inp=None):
        _DEBUG = DEBUG2
        if _DEBUG:
            print("in: %s" % binascii.hexlify(inp))
            print("cur: %d" % self.gen_obj)
        if inp and inp != "":
            for i in self.functions:
                if i["step"] == self.gen_obj or i["step"] == -1:
                    if i["func"] == "copy":
                        self.objects[self.gen_obj]["dizz"].obj_dict[i["dest"]]["cur"] = inp[i["start"]:i["end"]]
                    elif i["func"] == "adv_copy":
                        i["callback"](self.objects[self.gen_obj], inp)
                    elif i["func"] == "print_dizz":
                        pp = pprint.PrettyPrinter()
                        pp.pprint(self.objects[self.gen_obj]["dizz"].objects)
                    elif i["func"] == "print_field":
                        if not i["field"] is None:
                            print(self.objects[self.gen_obj]["dizz"].obj_dict[i["field"]]["cur"])
                        else:
                            obj = self.objects[self.gen_obj]["dizz"].cur_obj
                            if not obj is None:     #ugly!!!
                                print(self.objects[self.gen_obj]["dizz"].objects[obj]["cur"])
        
    def basic_copy(self, step, dest, start, end):
        obj = { "func"  :   "copy",
                "step"  :   step,
                "dest"  :   dest,
                "start" :   start,
                "end"   :   end,
                "callback"  :   None,
                }
        return obj
    
    def adv_copy(self, step, call):
        obj = { "func"  :   "adv_copy",
                "step"  :   step,
                "callback"  :   call,
                }
        return obj
    
    def print_dizz(self, step):
        obj = { "func"  :   "print_dizz",
                "step"  :   step
                }
        return obj
    
    def print_field(self, step, field):
        obj = { "func"  :   "print_field",
                "step"  :   step,
                "field" :   field
                }
        return obj

def get_session(options):
    if options.out_type == "eth":
        if os.geteuid() != 0:
            print("You must be root to send on eth.")
            sys.exit(1)
        if options.bind_addr:
            parser.error("option -b only valid for udp/tcp/tls/sctp output")
        if options.server:
            parser.error("option -s only valid for udp/tcp/tls/sctp")
        try:
            s = dizz_session(options.out_type, interface=options.out_dest, timeout=options.wait_recv)
        except Exception as e:
            if DEBUG:
                traceback.print_exc()
            parser.error("invalid arguments %s:%s : %s" % (options.out_dest, options.out_extra, str(e)))
    elif options.out_type == "file":
        if options.bind_addr:
            parser.error("option -b only valid for udp/tcp/tls/sctp output")
        if options.server:
            parser.error("option -s only valid for udp/tcp/tls/sctp")
        try:
            options.wait_send = 0
            options.reconnect = True
            s = dizz_session(options.out_type, filename=options.out_dest)
        except Exception as e:
            if DEBUG:
                traceback.print_exc()
            parser.error("invalid arguments %s : %s" % (options.out_dest, str(e)))
    elif options.out_type == "stdout" or options.out_type == "stdout-hex":
        if options.bind_addr:
            parser.error("option -b only valid for udp/tcp/tls/sctp output")
        if options.server:
            parser.error("option -s only valid for udp/tcp/tls/sctp")
        s = dizz_session(options.out_type)
    elif options.out_type == "cmd":
        if options.bind_addr:
            parser.error("option -b only valid for udp/tcp/tls/sctp output")
        if options.server:
            parser.error("option -s only valid for udp/tcp/tls/sctp")
        s = dizz_session(options.out_type, cmd=options.out_dest)
    elif options.out_type == "usb-dscr":
        if options.bind_addr:
            parser.error("option -b only valid for udp/tcp/tls/sctp output")
        if options.server:
            parser.error("option -s only valid for udp/tcp/tls/sctp")
        s = dizz_session(options.out_type, filename=options.out_dest, dest=options.out_extra, timeout=options.wait_recv)
    elif options.out_type == "usb-endp":
        if options.bind_addr:
            parser.error("option -b only valid for udp/tcp/tls/sctp output")
        if options.server:
            parser.error("option -s only valid for udp/tcp/tls/sctp")
        s = dizz_session(options.out_type, filename=options.out_dest, dest=options.out_extra, timeout=options.wait_recv)
    else:
        if not options.out_extra:
            parser.error("no src/dst ports given. use -e")
        if options.out_type == "tls":
            if options.client_cert != None and options.client_key == None:
                parser.error("no private key given")
            if options.client_cert == None and options.client_key != None:
                parser.error("no certificate given")
        try:
            if options.server and not options.bind_addr:
                parser.error("no bind address given")
            ports = options.out_extra.split(":")
            if ports[0] == 'rand':
                if options.server:
                    parser.error("cant listen on random port")
                sport = None
            else:
                sport = int(ports[0])
            if ports[1] == 'rand':
                if not options.server:
                    parser.error("cant send to random port")
                dport = None
            else:
                dport = int(ports[1])
            s = dizz_session(options.out_type, dest=options.out_dest, src=options.bind_addr, sport=sport, dport=dport, timeout=options.wait_recv, client_cert=options.client_cert, client_key=options.client_key, server_side=options.server)
        except Exception as e:
            if DEBUG:
                traceback.print_exc()
            if options.bind_addr != '':
                parser.error("invalid arguments %s, %s, %s : %s" % (options.out_dest, options.out_extra, options.bind_addr, str(e)))
            else:
                parser.error("invalid arguments %s, %s : %s" % (options.out_dest, options.out_extra, str(e)))
    return s

def read(session, options, rlen=None, interaction=None):
    d = b""
    reconnect = False
    try:
        reading = True
        while reading:
            r = session.recv()
            if not r:
                reading = False
                if DEBUG:
                    print("Read end on NONE")
            else:
                d += r
                if options.verbose > 2:
                    outp = binascii.hexlify(d[:1024])
                    if len(d) > 1024:
                        outp += b"..."
                    print("r: %s" % outp)
                if options.verbose > 3:
                    outp = d[:1024]
                    if len(d) > 1024:
                        outp += b"..."
                    print("r: %s" % outp)
                    #print str_to_bin(d)
            if not rlen is None:
                if len(d) >= rlen:
                    reading = False
    except (socket.timeout, ssl.SSLError):
        if options.verbose > 2:
            print("Read end on timeout")
        pass
    except socket.error as e:
        if options.verbose > 2:
            print("Read end on sock error '%s', reopening..." % str(e))
        if not interaction is None:
            interaction.gen_obj = 0
        reconnect = True
        if options.exit:
            sys.exit(1)
    except Exception as e:
        print("Cant read input: %s" % str(e))
        if options.verbose > 2:
            traceback.print_exc()
        sys.exit(1)
    return (d, reconnect)

if __name__ == '__main__':
    parser = OptionParser(usage="usage: %s [options] {dizzfile | ackfile}" % os.path.basename(sys.argv[0]), version=VERSION)
    parser.add_option("-v", help="Be verbose", dest="verbose", action="count", default=0)
    parser.add_option("-t", help="Dont mutate, just send first package", dest="test", action="store_true", default=False)
    parser.add_option("-o", help="Output type {eth, udp, tcp, tls, sctp, file, stdout, stdout-hex, cmd, usb-desc, usb-endp}", choices=["eth", "udp", "tcp", "tls", "sctp", "file", "stdout", "stdout-hex", "cmd", "usb-dscr", "usb-endp"], dest="out_type", default="stdout")
    parser.add_option("-d", type="string", help="Output destination (interface for eth, dst-ip for udp/tcp/tls/sctp, filename for file, command for cmd, usb device descriptor file for usb-*)", dest="out_dest", default=None)
    parser.add_option("-e", type="string", help="Output extra args (src:dst port for udp/tcp/sctp, src may be 'rand' for client side and dst may be 'rand' for server side, [DD|CD] for usb-dscr, EP nr. for usb-endp)", dest="out_extra", default=None)
    parser.add_option("-b", type="string", help="Interface address to bind udp/tcp/tls/sctp socket to", dest="bind_addr", default='')
    parser.add_option("-w", type="float", help="Time to wait between mutations (default 1)", metavar="SEC", dest="wait_send", default=1)
    parser.add_option("-W", type="float", help="Time to wait on receive (default 10)", metavar="SEC", dest="wait_recv", default=10)
    parser.add_option("-c", type="string", help="Certificate (PEM) for [d]tls client authentication", dest="client_cert", default=None)
    parser.add_option("-k", type="string", help="Private key (PEM) for [d]tls client authentication", dest="client_key", default=None)
    parser.add_option("-r", help="Reset connection after each mutation", dest="reconnect", action="store_true", default=False)
    parser.add_option("-R", help="Use recursive mutation mode (a lot of mutations!)", dest="recurse", action="store_true", default=False)
    parser.add_option("-s", help="Run in server side mode (accept connections)", dest="server", action="store_true", default=False)
    parser.add_option("-S", type="float", help="Start at the given step", dest="start_at", default=0)
    parser.add_option("-x", help="Exit on error", dest="exit", action="store_true", default=False)
    parser.add_option("-a", help="Read targets answer when running in non-interactive mode", dest="answer", action="store_true", default=False)
    parser.add_option("-q", help="Don't output any status messages", dest="quiet", action="store_true", default=False)
    parser.add_option("-B", help="Perform baseline request matching in non-interactive mode (implies -a)", dest="baseline", action="store_true", default=False)
    (options, args) = parser.parse_args()
    if len(args) != 1:
        parser.error("incorrect number of arguments")

    if options.baseline and not options.answer:
        options.answer = True

    if not options.quiet:
        print("Verbosity %d" % options.verbose)

    if options.verbose > 2:
        DEBUG=True
        if usb_present:
            usb.DEBUG=True
    if options.verbose > 3:
        DEBUG2=True
    if options.verbose > 4:
        DEBUG3=True
        
    session = get_session(options)
    
    l = dizz_library()
    dot = args[0].rfind(".")
    try:
        if args[0][dot:] == ".act":
            i = interaction(l, int(options.start_at))
            try:
                i.load(args[0])
            except Exception as e:
                if DEBUG:
                    traceback.print_exc()
                parser.error("invalid argument: %s: %s" % (args[0], str(e)))
            session.open()
            d = None
            done = False
            num = 1
            nxt = 1
            seq = 0
            while not done:
                in_sequence = True
                while in_sequence and not done:
                    reconnect = False
                    (o, rlen, done) = i.generate(options.recurse, options.test)
                    if options.verbose > 0:
                        current = i.get_current(options.recurse)
                        if not current is None:
                            print(str(num) + ": " + current)
                    if options.verbose > 2:
                        outp = binascii.hexlify(o[:1024])
                        if len(o) > 1024:
                            outp += b"..."
                        print("w: %s" % outp)
                    if options.verbose > 3:
                        outp = o[:1024]
                        if len(o) > 1024:
                            outp += b"..."
                        print("w: %s" % outp)
                        #print str_to_bin(o)
                    try:
                        session.send(o)
                    except Exception as e:
                        if not options.quiet:
                            print("Cant write output: %s" % str(e))
                            if options.verbose > 2:
                                traceback.print_exc()
                        if options.exit:
                            sys.exit(1)
                    (d, reconnect) = read(session, options, rlen, i)
                    i.operate(d)
                    if  options.reconnect or reconnect:
                        session.close()
                        session.open()
                    if i.gen_obj == 0:
                        in_sequence = False
                    if reconnect:
                        i.gen_obj = 0
                if options.test:
                    break
                if num >= nxt and options.verbose == 0:
                    if seq < 16:
                        seq = seq + 1
                        nxt = math.pow(2,seq)
                    else:
                        nxt = nxt + math.pow(2,seq)                
                    print(num)
                num = num + 1
                time.sleep(options.wait_send)
        else:
            d = dizz(l)
            try:
                d.load(args[0])
            except Exception as e:
                if options.verbose > 2:
                    traceback.print_exc()
                parser.error("invalid argument: %s: %s" % (args[0], str(e)))
            run = True
            num = 1
            nxt = 1
            seq = 0
            start = int(options.start_at)
            baseline = b""
            session.open()
            if options.baseline:
                if options.verbose > 0:
                    print("Performing baseline request")
                newd =  copy.deepcopy(d)
                newd.operate()
                o = newd.generate()
                session.send(o)
                (baseline, _) = read(session, options)
                if options.verbose > 1:
                    print("Received baseline answer of length %d" % len(baseline))
            if start > 0:
                while start > 0 and run:
                    run = d.mutate(options.recurse)
                    start = start - 1
                num = int(options.start_at)
            if not run:
                sys.exit(0)
            while run:
                d.operate()
                o = d.generate()
                if options.verbose > 0:
                    current = d.get_current(options.recurse)
                    if not current is None:
                        print(str(num) + ": " + current)
                if options.verbose > 2:
                    print(binascii.hexlify(o[:1024]))
                    #print str_to_bin(o)
                try:
                    session.send(o)
                except Exception as e:
                    if not options.quiet:
                        print("Cant write output: %s" % str(e))
                        if options.verbose > 2:
                            traceback.print_exc()
                    if options.exit:
                        sys.exit(1)
                if options.answer:
                    (r, reconnect) = read(session, options)
                    if reconnect:
                        session.close()
                        session.open()
                    if options.baseline:
                        if r != baseline:
                            print("!!! Baseline missmatch !!!")
                            if options.verbose > 0 and options.verbose < 3:
                                if len(r) > 1024:
                                    r = r[:1024] + b"..."
                                print("Received %s" % r)
                if options.test:
                    break
                run = d.mutate(options.recurse)
                if num >= nxt and options.verbose == 0:
                    if seq < 16:
                        seq = seq + 1
                        nxt = math.pow(2,seq)
                    else:
                        nxt = nxt + math.pow(2,seq)                
                    print(num)
                num = num + 1
                time.sleep(options.wait_send)
                if options.reconnect:
                    session.close()
                    session.open()
    except KeyboardInterrupt:
        if session.is_open:
            if not options.quiet:
                print("closing session...")
            session.close()
    except Exception as e:
        print(e)
        if options.verbose > 1:
            traceback.print_exc()
    sys.exit(0)
