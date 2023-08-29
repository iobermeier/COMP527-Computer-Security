"""Do before running for the first time:
-ensure Python2 is chosen
-ensure dpkt is installed using 'python2 -m pip install dpkt'
-have the given pcap downloaded with file type as .pcap
"""
import dpkt
import sys
import socket

def detect():
    if len(sys.argv) >= 3:
        return
    arg = sys.argv[1]
    file = open(arg, 'rb')
    pcap = dpkt.pcap.Reader(file)
    address_dict = {}

    for ts, buf in pcap:

        try:
            ethern = dpkt.ethernet.Ethernet(buf)
            eth_data = ethern.data

            if dpkt.ip.IP_PROTO_TCP == eth_data.p:
                tcp_syn = eth_data.data
                syn_flag = (tcp_syn.flags & dpkt.tcp.TH_SYN) != 0
                syn_ack_flag = (tcp_syn.flags & dpkt.tcp.TH_ACK) != 0
                dst_addr = socket.inet_ntoa(eth_data.dst)
                src_addr = socket.inet_ntoa(eth_data.src)

                if syn_flag and syn_ack_flag:

                    if dst_addr in address_dict:
                        address_dict[dst_addr]['SYN-ACK'] = 1 + address_dict[dst_addr]['SYN-ACK']
                    else:
                        address_dict[dst_addr] = {'SYN': 0, 'SYN-ACK': 1}

                if syn_flag and not syn_ack_flag:

                    if src_addr in address_dict:
                        address_dict[src_addr]['SYN'] = 1 + address_dict[src_addr]['SYN']
                    else:
                        address_dict[src_addr] = {'SYN': 1, 'SYN-ACK': 0}



        except:
            pass

    file.close()

    v = {}
    for k in address_dict.keys():
        dict_key=address_dict[k]
        v[k] = dict_key['SYN'] - 3 * dict_key['SYN-ACK']
        if v[k]>0:
            print(k)





if __name__ == "__main__":
    detect()
