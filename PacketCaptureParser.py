from scapy.all import *
import pyshark
import concurrent.futures


def radius_session_write(access_request_id, ip_src, ip_dst):
    pcap = rdpcap('/home/atul/Documents/pcaps/radius.pcap')
    for i in access_request_id:
        for pkt in pcap:
            source_ip = str(pkt['IP'].src)
            dst_ip = str(pkt['IP'].dst)
            if int(pkt['RADIUS'].id) == i and (ip_src in (source_ip, dst_ip) and ip_dst in (source_ip, dst_ip)):
                wrpcap('/home/atul/Documents/pcaps/radius_session.pcap', pkt, append=True)
    return 'Done'


def radius_session(pcap_file, calling_station_id, protocol, access_request_id):
    for pkt in pcap_file:
        if protocol in pkt:
            if (int(pkt[protocol].code)) == 1:
                mac_addr = str(pkt['RADIUS'].calling_station_id)
                if mac_addr == calling_station_id:
                    access_request_id.append(int(pkt['radius'].id))
    return access_request_id


def radiusonly(protocol):
    pcap_file_radius = rdpcap('/home/atul/Documents/pcaps/test.pcap')
    for pkt in pcap_file_radius:
        if protocol in pkt:
            wrpcap('/home/atul/Documents/pcaps/radius.pcap', pkt, append=True)
        else:
            pass
    return "Radius packets have been segregated"


pcap_file = pyshark.FileCapture('/home/atul/Documents/pcaps/test.pcap')
calling_station_id = '6470334D3BD5'
protocol = 'RADIUS'
access_request_id = []
ip_src = '172.19.111.3'
ip_dst = '172.16.32.25'

with concurrent.futures.ProcessPoolExecutor() as executor:
    radius = executor.submit(radiusonly, protocol)
    result = executor.submit(radius_session(pcap_file, calling_station_id, protocol,access_request_id))

packet_capture = radius_session_write(set(access_request_id), ip_src, ip_dst)

print(radius.result())
print(result)
print(packet_capture)
