#!/usr/bin/perl -w
#
#  parse_lsusb.pl
#  
#  Copyright 2013 Daniel "The Man" Mende, aka The Weazy Master of Mass Destruction (sorry, my girlfriend was here) <mail@c0decafe.de>
#  
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#  
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#  
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#  MA 02110-1301, USA.


# use strictness
use strict;
# print non-fatal warnings
use warnings;
use Encode qw/encode/;

binmode STDOUT, ":raw";

my $device;
my %dd;     #device_descriptor
my %cd;     #configuration_descriptor
my %id;     #interface descriptor
my %ed;     #endpoint descriptor

my $in_devicedescr = 0;
my $in_configurationdescr = 0;
my $in_interfacedescr = 0;
my $in_endpointdescr = 0;

sub push_dd {
    print STDOUT << "EOF";
DD={ "bLength"              :   $dd{"bLength"},
     "bDescriptorType"      :   $dd{"bDescriptorType"},
     "bcdUSB"               :   "$dd{"bcdUSB"}",
     "bDeviceClass"         :   $dd{"bDeviceClass"},
     "bDeviceSubClass"      :   $dd{"bDeviceSubClass"},
     "bDeviceProtocol"      :   $dd{"bDeviceProtocol"},
     "bMaxPacketSize"       :   $dd{"bMaxPacketSize0"},
     "idVendor"             :   $dd{"idVendor"},
     "idProduct"            :   $dd{"idProduct"},
     "bcdDevice"            :   "$dd{"bcdDevice"}",
     "iManufacturer"        :   $dd{"iManufacturer"},
     "iManufacturer_str"    :   "$dd{"iManufacturer_str"}",
     "iProduct"             :   $dd{"iProduct"},
     "iProduct_str"         :   "$dd{"iProduct_str"}",
     "iSerial"              :   $dd{"iSerial"},
     "iSerial_str"          :   "$dd{"iSerial_str"}",
     "bNumConfigurations"   :   $dd{"bNumConfigurations"},
    "CD" :  [
EOF
}

sub end_dd {
    print STDOUT << "EOF";
    ] #end-CD
}
EOF
}

sub push_cd {
    print STDOUT << "EOF";
    {   "bLength"               :   $cd{"bLength"},
        "bDescriptorType"       :   $cd{"bDescriptorType"},
        "wTotalLength"          :   $cd{"wTotalLength"},
        "bNumInterfaces"        :   $cd{"bNumInterfaces"},
        "bConfigurationValue"   :   $cd{"bConfigurationValue"},
        "iConfiguration"        :   $cd{"iConfiguration"},
        "iConfiguration_str"    :   "$cd{"iConfiguration_str"}",
        "bmAttributes"          :   $cd{"bmAttributes"},
        "MaxPower"              :   $cd{"MaxPower"},
        "ID" :  [
EOF
}

sub end_cd {
    print STDOUT << "EOF";
        ] #end-ID
    },
EOF
}

sub push_id {
    print STDOUT << "EOF";
            {   "bLength"           :   $id{"bLength"},
                "bDescriptorType"   :   $id{"bDescriptorType"},
                "bInterfaceNumber"  :   $id{"bInterfaceNumber"},
                "bAlternateSetting" :   $id{"bAlternateSetting"},
                "bNumEndpoints"     :   $id{"bNumEndpoints"},
                "bInterfaceClass"   :   $id{"bInterfaceClass"},
                "bInterfaceSubClass":   $id{"bInterfaceSubClass"},
                "bInterfaceProtocol":   $id{"bInterfaceProtocol"},
                "iInterface"        :   $id{"iInterface"},
                "iInterface_str"    :   "$id{"iInterface_str"}",
                "EP"    :   [
EOF
}

sub end_id {
    print STDOUT << "EOF";
                ] #end-EP
            },
EOF
}

sub push_ed {
    print STDOUT << "EOF";
                    {   "bLength"           :   $ed{"bLength"},
                        "bDescriptorType"   :   $ed{"bDescriptorType"},
                        "bEndpointAddress"  :   $ed{"bEndpointAddress"},
                        "bmAttributes"      :   $ed{"bmAttributes"},
                        "wMaxPacketSize"    :   $ed{"wMaxPacketSize"},
                        "bInterval"         :   $ed{"bInterval"},
                    },
EOF
}

while (<STDIN>) {
    
    next if ($_ =~ m/^$/); #skip empty lines
    next if ($_ =~ m/^\s*#/); #skip comments
    
    if ($_ =~ m/^Bus\s+(\d+)\s+Device\s+(\d+):\s+ID\s+([0-9a-fA-F]+):([0-9a-fA-F]+)\s+/) {
        #~ print "Device found:\n";
        #~ print $1.":".$2."\t"."ID: ".$3.":".$4."\n";
        $device = $3.":".$4;
        next;
    }
    if ($_ =~ m/^Device Descriptor:/) {
        #print "Creating new Device Descriptor\n";
        if ($in_configurationdescr == 1) {
            push_cd();
            end_cd();
            end_dd();
            $in_configurationdescr = 0;
        } elsif ($in_interfacedescr == 1) {
            push_id();
            end_id();
            end_cd();
            end_dd();
            $in_interfacedescr = 0;
        } elsif ($in_endpointdescr == 1) {
            push_ed();
            end_id();
            end_cd();
            end_dd();
            $in_endpointdescr = 0;
        }
        %dd = qw();
        $in_devicedescr = 1;
        next;
    }
    if ($_ =~ m/\s+bLength\s+(\d+)/) {
        #print "bLength: ".$1."\n";
        $dd{"bLength"} = $1 if $in_devicedescr;
        $cd{"bLength"} = $1 if $in_configurationdescr;
        $id{"bLength"} = $1 if $in_interfacedescr;
        $ed{"bLength"} = $1 if $in_endpointdescr;
        next;
    }
    if ($_ =~ m/\s+bDescriptorType\s+(\d+)/) {
        #print "bDescriptorType: ".$1."\n";
        $dd{"bDescriptorType"} = $1 if $in_devicedescr;
        $cd{"bDescriptorType"} = $1 if $in_configurationdescr;
        $id{"bDescriptorType"} = $1 if $in_interfacedescr;
        $ed{"bDescriptorType"} = $1 if $in_endpointdescr;
        next;
    }
    
    
    if ($_ =~ m/\s+bcdUSB\s+(\d+\.\d+)/) {
        #print "bcdUSB: ".$1."\n";
        $dd{"bcdUSB"} = $1 if $in_devicedescr;
        next;
    }
    if ($_ =~ m/\s+bDeviceClass\s+(\d+)/) {
        #print "bDeviceClass: ".$1."\n";
        $dd{"bDeviceClass"} = $1 if $in_devicedescr;
        next;
    }
    if ($_ =~ m/\s+bDeviceSubClass\s+(\d+)/) {
        #print "bDeviceSubClass: ".$1."\n";
        $dd{"bDeviceSubClass"} = $1 if $in_devicedescr;
        next;
    }
    if ($_ =~ m/\s+bDeviceProtocol\s+(\d+)/) {
        #print "bDeviceProtocol: ".$1."\n";
        $dd{"bDeviceProtocol"} = $1 if $in_devicedescr;
        next;
    }
    if ($_ =~ m/\s+bMaxPacketSize0\s+(\d+)/) {
        #print "bMaxPacketSize0: ".$1."\n";
        $dd{"bMaxPacketSize0"} = $1 if $in_devicedescr;
        next;
    }
    if ($_ =~ m/\s+idVendor\s+(0x[0-9a-fA-F]+)/) {
        #print "idVendor: ".$1."\n";
        $dd{"idVendor"} = $1 if $in_devicedescr;
        next;
    }
    if ($_ =~ m/\s+idProduct\s+(0x[0-9a-fA-F]+)/) {
        #print "idProduct: ".$1."\n";
        $dd{"idProduct"} = $1 if $in_devicedescr;
        next;
    }
    if ($_ =~ m/\s+bcdDevice\s+(\d+\.\d+)/) {
        #print "bcdDevice: ".$1."\n";
        $dd{"bcdDevice"} = $1 if $in_devicedescr;
        next;
    }
    if ($_ =~ m/\s+iManufacturer\s+(\d+)/) {
        #print "iManufacturer: ".$1."\n";
        $dd{"iManufacturer"} = $1 if $in_devicedescr;
        if ($_ =~ m/\s+iManufacturer\s+(\d+)\s(.+)$/) {
            $dd{"iManufacturer_str" } = $2;
        } else {
            $dd{"iManufacturer_str" } = "";
        }
        next;
    }
    if ($_ =~ m/\s+iProduct\s+(\d+)/) {
        #print "iProduct: ".$1."\n";
        $dd{"iProduct"} = $1 if $in_devicedescr;
        if ($_ =~ m/\s+iProduct\s+(\d+)\s(.+)$/) {
            $dd{"iProduct_str" } = $2;
        } else {
            $dd{"iProduct_str" } = "";
        }
        next;
    }
    if ($_ =~ m/\s+iSerial\s+(\d+)/) {
        #print "iSerial: ".$1."\n";
        $dd{"iSerial"} = $1 if $in_devicedescr;
        if ($_ =~ m/\s+iSerial\s+(\d+)\s(.+)$/) {
            $dd{"iSerial_str" } = $2;
        } else {
            $dd{"iSerial_str" } = "";
        }
        next;
    }
    if ($_ =~ m/\s+bNumConfigurations\s+(\d+)/) {
        #print "bNumConfigurations: ".$1."\n";
        $dd{"bNumConfigurations"} = $1 if $in_devicedescr;
        next;
    }

    
    ################# 
    if ($_ =~ m/\s+Configuration Descriptor:/) {
        #print "Creating new Configuration Descriptor\n";
        if ($in_devicedescr == 1) {
            push_dd();
            $in_devicedescr = 0;
        }
        if ($in_configurationdescr == 1) {
            end_cd();
            $in_configurationdescr = 0;
        } elsif ($in_interfacedescr == 1) {
            push_id();
            end_id();
            end_cd();
            $in_interfacedescr = 0
        } elsif ($in_endpointdescr == 1) {
            push_ed();
            end_id();
            end_cd();
            $in_endpointdescr = 0;
        }
        %cd = qw();
        $in_configurationdescr = 1;
        next;
    }
    if ($_ =~ m/\s+wTotalLength\s+(\d+)/) {
        #print "wTotalLength: ".$1."\n";
        $cd{"wTotalLength"} = $1 if $in_configurationdescr;
        next;
    }
    if ($_ =~ m/\s+bNumInterfaces\s+(\d+)/) {
        #print "bNumInterfaces: ".$1."\n";
        $cd{"bNumInterfaces"} = $1 if $in_configurationdescr;
        next;
    }
    if ($_ =~ m/\s+bConfigurationValue\s+(\d+)/) {
        #print "bConfigurationValue: ".$1."\n";
        $cd{"bConfigurationValue"} = $1 if $in_configurationdescr;
        next;
    }
    if ($_ =~ m/\s+iConfiguration\s+(\d+)/) {
        #print "iConfiguration: ".$1."\n";
        $cd{"iConfiguration"} = $1 if $in_configurationdescr;
        if ($_ =~ m/\s+iConfiguration\s+(\d+)\s(.+)$/) {
            $cd{"iConfiguration_str" } = $2;
        } else {
            $cd{"iConfiguration_str" } = "";
        }
        next;
    }
    if ($_ =~ m/\s+bmAttributes\s+(0x[0-9a-fA-F]+)/) {
        #print "bmAttributes: ".$1."\n";
        $cd{"bmAttributes"} = $1 if $in_configurationdescr;
        next;
    }
    if ($_ =~ m/\s+MaxPower\s+(\d+)mA/) {
        #print "MaxPower: ".$1."\n";
        $cd{"MaxPower"} = $1 / 2 if $in_configurationdescr;
        next;
    }
    
    #################
    if ($_ =~ m/^\s+Interface Descriptor:/) {
        #print "Creating new Interface Descriptor\n";
        #print "cd: ".$in_configurationdescr."  id: ".$in_interfacedescr."ed: ".$in_endpointdescr."\n";
        if ($in_configurationdescr == 1) {
            push_cd();
            $in_configurationdescr = 0;
        } elsif ($in_interfacedescr == 1) {
            push_id();
            end_id();
            $in_interfacedescr = 0;
        } elsif ($in_endpointdescr == 1) {
            push_ed();
            end_id();
            $in_endpointdescr = 0;
        }
        %id = qw();
        $in_interfacedescr = 1;
        next;
    }
    
    if ($_ =~ m/\s+bInterfaceNumber\s+(\d+)/) {
        #print "bInterfaceNumber: ".$1."\n";
        $id{"bInterfaceNumber"} = $1 if $in_interfacedescr;
        next;
    }
    if ($_ =~ m/\s+bInterfaceNumber\s+(\d+)/) {
        #print "bInterfaceNumber: ".$1."\n";
        $id{"bInterfaceNumber"} = $1 if $in_interfacedescr;
        next;
    }
    if ($_ =~ m/\s+bAlternateSetting\s+(\d+)/) {
        #print "bAlternateSetting: ".$1."\n";
        $id{"bAlternateSetting"} = $1 if $in_interfacedescr;
        next;
    }
    if ($_ =~ m/\s+bNumEndpoints\s+(\d+)/) {
        #print "bNumEndpoints: ".$1."\n";
        $id{"bNumEndpoints"} = $1 if $in_interfacedescr;
        next;
    }
    if ($_ =~ m/\s+bInterfaceClass\s+(\d+)/) {
        #print "bInterfaceClass: ".$1."\n";
        $id{"bInterfaceClass"} = $1 if $in_interfacedescr;
        next;
    }
    if ($_ =~ m/\s+bInterfaceSubClass\s+(\d+)/) {
        #print "bInterfaceSubClass: ".$1."\n";
        $id{"bInterfaceSubClass"} = $1 if $in_interfacedescr;
        next;
    }
    if ($_ =~ m/\s+bInterfaceProtocol\s+(\d+)/) {
        #print "bInterfaceProtocol: ".$1."\n";
        $id{"bInterfaceProtocol"} = $1 if $in_interfacedescr;
        next;
    }
    if ($_ =~ m/\s+iInterface\s+(\d+)/) {
        #print "iInterface: ".$1."\n";
        $id{"iInterface"} = $1 if $in_interfacedescr;
        if ($_ =~ m/\s+iInterface\s+(\d+)\s(.+)$/) {
            $id{"iInterface_str" } = $2;
        } else {
            $id{"iInterface_str" } = "";
        }
        next;
    }
    
    
    
    #################
    if ($_ =~ m/\s+Endpoint Descriptor:/) {
        #print "Creating new Endpoint Descriptor\n";
        if ($in_interfacedescr == 1) {
            push_id();
            $in_interfacedescr = 0;
        } elsif ($in_endpointdescr == 1) {
            push_ed();
        }
        %ed = qw();
        $in_endpointdescr = 1;
        next;
    }
    if ($_ =~ m/\s+bEndpointAddress\s+(0x[0-9a-fA-F]+)/) {
        #print "bEndpointAddress: ".$1."\n";
        $ed{"bEndpointAddress"} = $1 if $in_endpointdescr;
        next;
    }
    if ($_ =~ m/\s+bmAttributes\s+(\d+)/) {
        #print "bmAttributes: ".$1."\n";
        $ed{"bmAttributes"} = $1 if $in_endpointdescr;
        next;
    }
    if ($_ =~ m/\s+wMaxPacketSize\s+(0x[0-9a-fA-F]+)/) {
        #print "wMaxPacketSize: ".$1."\n";
        $ed{"wMaxPacketSize"} = $1 if $in_endpointdescr;
        next;
    }
    if ($_ =~ m/\s+bInterval\s+(\d+)/) {
        #print "bInterval: ".$1."\n";
        $ed{"bInterval"} = $1 if $in_endpointdescr;
        next;
    }
    
    #print STDERR ">>>> ".$_;
        
}

if ($in_configurationdescr == 1) {
    push_cd();
    end_cd();
    end_dd();
} elsif ($in_interfacedescr == 1) {
    push_id();
    end_id();
    end_cd();
    end_dd();
} elsif ($in_endpointdescr == 1) {
    push_ed();
    end_id();
    end_cd();
    end_dd();
}
