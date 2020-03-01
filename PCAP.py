import sys
from scapy.all import *
import pyshark

pcap_file = rdpcap('/home/atul/Downloads/wiredradiusfiltered.pcap')


def packet_capture(pcap_file):
    for pkt in pcap_file:
        if 'RADIUS' in pkt:
            wrpcap('radius.pcap', pkt, append=True)
            if pkt['RADIUS'].code == 1:
                wrpcap('request.pcap', pkt, append=True)
            elif pkt['RADIUS'].code == 11 or pkt['RADIUS'].code == 2:
                wrpcap('challenge.pcap', pkt, append=True)
            else:
                pass
        else:
            pass
    filtered = pyshark.FileCapture('challenge.pcap')
    packet_id = session(filtered)
    radiusonly = rdpcap('radius.pcap')
    final = final_pcap(packet_id, radiusonly)
    return final


def session(filtered):
    State = '33:37:43:50:4d:53:65:73:73:69:6f:6e:49:44:3d:35:34:64:31:66:32:30:36:30:30:30:30:30:30:30:32:35:39:35:39:36:66:34:63:3b:32:39:53:65:73:73:69:6f:6e:49:44:3d:69:73:65:2f:32:38:34:36:30:34:33:38:38:2f:31:31:30:30:37:3b'
    user_name = 'employeealex'
    radius_id = []
    for pkt in filtered:
        if pkt['RADIUS'].state == State:
            radius_id.append(pkt['RADIUS'].id)
        elif str(pkt['RADIUS'].User_Name) == user_name and (int(pkt['RADIUS'].code) == 2 or int(pkt['RADIUS'].code) == 2):
            radius_id.append(pkt['RADIUS'].id)
        else:
            ab = str(pkt['RADIUS'].User_Name)
            print(type(ab))
            print(type(user_name))
            pass
    return radius_id


def final_pcap(packet_id, radiusonly):
    for i in packet_id:
        for pkt in radiusonly:
            if pkt['RADIUS'].id == int(i):
                wrpcap('radiusspecific.pcap', pkt, append=True)
    return 0


result = packet_capture(pcap_file)
print(result)
