##! This script reconfigures some of the builtin Bro scripts to suit certain SecurityOnion uses.

# Commenting out for Bro 2.2
# redef PacketFilter::all_packets = F;

redef capture_filters = { ["bpf.conf"] = "ip or not ip" };

redef Notice::emailed_types += { BPFConf::InvalidFilter };
