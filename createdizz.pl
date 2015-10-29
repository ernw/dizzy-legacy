#!/usr/bin/perl

$debug=1;
$myproto="icmpv6";
$tshark="tshark";


$_dizzfile="my.dizz";
$capturefile="/tmp/test2.pcap";
$filter="frame.number==1";

open(OUT,">$_dizzfile");
print OUT <<EOF;
import binascii

name = "mydizz"

objects = [
EOF

extract_tshark();
$i=0;
foreach(@dizz_1)
{
$data = $dizz_2[$i];
if(length($data) == 1) { $data = "0".$data; }
print OUT 'field("'.$dizz_1[$i].'", '.(length($dizz_2[$i])*4).', binascii.unhexlify(b"'.$data.'"), none),'."\n";
$i++;
}
print OUT <<EOF;
    ]

functions = []
EOF

close OUT;


############SUBS

sub extract_tshark
{
$start=0;
$cmd="$tshark -r $capturefile -2 -T pdml -R $filter";
$ret=`$cmd > createdizz.xml`;
open(XML,"createdizz.xml");
while (<XML>)
{
($tag)=/^\s*<\/{0,1}(\w+)/;
($name)=/\sname="([\w\d\.]*)"/;
$name="unknown" if length($name)<1;
($pos)=/\spos="(\d*)"/;
($value)=/\svalue="([\w\d]*)"/;
print $_ if $debug;
print "($tag,$name,$pos,$value)\n" if $debug;

if (($tag eq "proto") && ($name eq $myproto))
{
	$start++;
	print "*****START*****\n" if $debug;
	next;
}
if (($start==1)&&($tag eq "proto"))
{
	last;
}

if (($start==1)&&(defined $value)&&($pos!=$lpos))
{
	next if /">$/;
	push(@dizz_1,$name);
	push(@dizz_2,$value);
	print "PUSHED $name $value\n" if $debug;
}

$lpos=$pos;
}
close XML
}



