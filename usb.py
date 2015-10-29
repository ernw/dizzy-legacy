#!/usr/bin/env python3

#       usb.py
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

import os
import select
import sys
import threading
import traceback

root = os.path.dirname(__file__) or os.getcwd()
sys.path.append(os.path.join(root, "usb"))
del root

from USB import *
from USBDevice import *
from USBConfiguration import *
from USBInterface import *
from USBEndpoint import *
from Facedancer import *
from MAXUSBApp import *
from serial import Serial, PARITY_NONE
from serial.serialutil import SerialException

import tools

DEBUG = False
DEFAULT_TTY = "/dev/ttyUSB0"

class dizzyUSBDevice(USBDevice):
    name = "dizzy USB device"
    
    class dizzyUSBInterface(USBInterface):
        name = "dizzy USB interface"
        
        def __init__(self, ID, verbose=0):
            endpoints = [ USBEndpoint(
                                ID["EP"].index(i),              # endpoint number
                                
                                ################# fill in data from file ################
                                USBEndpoint.direction_in,
                                USBEndpoint.transfer_type_interrupt,
                                USBEndpoint.sync_type_none,
                                USBEndpoint.usage_type_data,
                                #########################################################
                                
                                i["wMaxPacketSize"],            # max packet size
                                i["bInterval"],                 # polling interval, see USB 2.0 spec Table 9-13
                                self.handle_buffer_available    # handler function
                            ) for i in ID["EP"] ]

            USBInterface.__init__(
                    self,
                    ID["bInterfaceNumber"],     # interface number
                    ID["bAlternateSetting"],    # alternate setting
                    ID["bInterfaceClass"],      # interface class
                    ID["bInterfaceSubClass"],   # subclass
                    ID["bInterfaceProtocol"],   # protocol
                    ID["iInterface"],           # string index
                    verbose,
                    endpoints
            )
            
        def handle_buffer_available(self):
            pass

    def __init__(self, maxusb_app, DD, verbose=0, data="", fuzz_dscr=""):
        config = [  USBConfiguration(
                        DD["CD"].index(i),          # index
                        i["iConfiguration_str"],    # string desc
                        [ self.dizzyUSBInterface(j, verbose=verbose) 
                            for j in i["ID"] ]      # interfaces
                    ) for i in DD["CD"] ]

        USBDevice.__init__(
            self,
            maxusb_app,
            DD["bDeviceClass"],             # device class
            DD["bDeviceSubClass"],          # device subclass
            DD["bDeviceProtocol"],          # protocol release number
            DD["bMaxPacketSize"],           # max packet size for endpoint 0
            DD["idVendor"],                 # vendor id
            DD["idProduct"],                # product id
            self.bcd2int(DD["bcdDevice"]),  # device revision
            DD["iManufacturer_str"],        # manufacturer string
            DD["iProduct_str"],             # product string
            DD["iSerial_str"],              # serial number string
            config,
            verbose=verbose
        )
        for i in DD["CD"]:
            for j in i["ID"]:
                self.strings.insert(j["iInterface"], j["iInterface_str"])
        self.data = data
        self.fuzz_dscr = fuzz_dscr
        self.dd_sent = False
        self.cd_sent = False
        self.scr_recieved = False
                            
    def bcd2int(self, bcd):
        tmp = bcd.split(".")
        return (int(tmp[0]) << 8) + int(tmp[1])

    def handle_get_descriptor_request(self, req):
        dtype  = (req.value >> 8) & 0xff
        dindex = req.value & 0xff
        lang   = req.index
        n      = req.length

        response = None

        if self.verbose > 2:
            print(self.name, ("received GET_DESCRIPTOR req %d, index %d, " \
                    + "language 0x%04x, length %d") \
                    % (dtype, dindex, lang, n))

        if dtype == USB.desc_type_device and self.fuzz_dscr == "DD":
            response = self.data
        elif dtype == USB.desc_type_configuration and self.fuzz_dscr == "CD":
            response = self.data
            #add IDs and EDs to response!
        else:
            response = self.descriptors.get(dtype, None)
            if callable(response):
                response = response(dindex)

        if not response is None:
            n = min(n, len(response))
            self.maxusb_app.verbose += 1
            self.maxusb_app.send_on_endpoint(0, response[:n])
            self.maxusb_app.verbose -= 1

            if self.verbose > 5:
                print(self.name, "sent", n, "bytes in response")
        else:
            self.maxusb_app.stall_ep0()
        
        if n == len(response):            
            if dtype == USB.desc_type_device:
                self.dd_sent = True
            elif dtype == USB.desc_type_configuration:
                self.cd_sent = True
                
    def handle_set_configuration_request(self, req):
        if self.verbose > 2:
            print(self.name, "received SET_CONFIGURATION request")

        # configs are one-based
        self.config_num = req.value - 1
        self.configuration = self.configurations[self.config_num]
        self.state = USB.state_configured

        # collate endpoint numbers
        self.endpoints = { }
        for i in self.configuration.interfaces:
            for e in i.endpoints:
                self.endpoints[e.number] = e

        # HACK: blindly acknowledge request
        self.ack_status_stage()
        self.scr_recieved = True
        
class dizzyUSB(object):    
    def __init__(self, filename, timeout, device=DEFAULT_TTY, data="", fuzz_dscr=""):
        self.filename = filename
        self.timeout = timeout
        self.device = device
        self.data = data
        self.fuzz_dscr = fuzz_dscr
        self.sp = None
        self.d = None
    
    def open(self, dst=""):
        if DEBUG:
            verbose = 1
        else:
            verbose = 0
        ns = {}
        with open(self.filename) as f:
            exec(compile(f.read(), self.filename, 'exec'), ns)
        DD = ns["DD"]
        success = False
        if DEBUG:
            print("setting up facedancer")
        sys.__stdout__.flush()
        while not success:
            try:
                self.sp = Serial(self.device, 115200, parity=PARITY_NONE, timeout=2)
                self.fd = Facedancer(self.sp, verbose=verbose)
                self.app = MAXUSBApp(self.fd, verbose=verbose)
                self.d = dizzyUSBDevice(self.app, DD, verbose, self.data, self.fuzz_dscr)
                success = True
            except:
                time.sleep(0.1)
        
        self.d.connect()
        self.t = threading.Thread(target=self.run)
        self.ep = None
        self.opened = False
        
        if not dst == "":
            self.ep = int(dst)
        self.t.start()
        self.opened = True
        if DEBUG:
            print("Waiting for USB to setup...")
        if self.fuzz_dscr == "":
            time.sleep(2)
        else:
            times = self.timeout
            while (not (self.d.dd_sent and self.d.cd_sent and self.d.scr_recieved and False)) and times > 0:
                if DEBUG:
                    sys.__stdout__.write(".")
                    sys.__stdout__.flush()
                time.sleep(0.1)
                times -= 1
            if DEBUG:
                sys.__stdout__.write("\n")
                sys.__stdout__.flush()
            if times <= 0 and DEBUG:
                print("timeout reached, canceled!")
                #raise
                return
        if DEBUG:
            print("USB setup complete.")
    
    def run(self):
        try:
            self.d.run()            
        except SerialException:
            pass
        except select.error:
            pass
        except OSError:
            pass
        except TypeError:
            pass
        except IndexError:
            pass
        except Exception as e:
            if DEBUG:
                traceback.print_exc()
            print(e)
        self.opened = False
    
    def close(self):
        if not self.open:
            return
        if not self.d is None:
            try:
                self.d.disconnect()
            except IndexError:
                pass
            except SerialException:
                pass
            except ValueError:
                pass
            except Exception as e:
                if DEBUG:
                    traceback.print_exc()
                print(e)
        if not self.sp is None:
            self.sp.close()
        self.open = False
            
    def read(self):
        pass
    
    def write(self, data):
        if not self.ep is None:
            while not self.opened:
                time.sleep(0.1)
            try:
                self.app.send_on_endpoint(self.ep, data)
            except Exception as e:
                #~ if DEBUG:
                    #~ traceback.print_exc()
                #~ print(e)
                raise e

