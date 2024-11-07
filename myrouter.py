#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import time
import switchyard
import threading
from switchyard.lib.userlib import *
from switchyard.lib.address import IPv4Network, IPv4Address
import ipaddress

class ARPTableEntry:
    def __init__(self,ipaddr,macaddr):
        self.ipaddr=ipaddr
        self.macaddr=macaddr
        self.timestamp=time.time()

    def is_oldEntry(self,timeout):
        return (time.time()-self.timestamp)>=timeout

class ARPTable:
    def __init__(self,timeout=100):
        self.table={}
        self.timeout=timeout

    def addEntry(self,ipaddr,macaddr):
        self.table[ipaddr]=ARPTableEntry(ipaddr,macaddr)

    def get_macaddr(self,ipaddr):
        if ipaddr in self.table:
            entry=self.table[ipaddr]
            print(f"get next_hop_mac:{entry.macaddr} ")
            return entry.macaddr
        else:
            print("not found in arptable next_hop_mac")
            return None

    def cleanup(self):
        oldEntrys=[key for key,entry in self.table.items() if entry.is_oldEntry(self.timeout)]
        print("delete timeout entry:")
        for key in oldEntrys:
            del self.table[key]

   
class RoutingTableEntry:
    def __init__(self, network, netmask, next_hop, interface):
        network_obj = IPv4Network(f"{network}/{netmask}", strict=False)
        self.network = network_obj.network_address 
        self.netmask = netmask
        self.next_hop = next_hop
        self.interface = interface
        self.prefixlen = network_obj.prefixlen

    def __repr__(self):
        return f"{self.network}/{self.netmask} -> Next hop: {self.next_hop} on {self.interface}"


class RoutingTable:
    def __init__(self):
        self.entries = []

    def addEntry(self,network,netmask,next_hop,interface):
        entry = RoutingTableEntry(network, netmask, next_hop, interface)
        self.entries.append(entry)

    def lookup(self,ip_address):
        print("begin match.")
        next_hop_ip=IPv4Address('0.0.0.0')
        next_interface='None'
        best_prefix_len=0
        ip=IPv4Address(ip_address)

        for entry in self.entries:
            if (int(ip_address) & int(entry.netmask)) == (int(entry.network)& int(entry.netmask)) and entry.prefixlen>best_prefix_len:
                next_hop_ip=entry.next_hop
                next_interface=entry.interface
                best_prefix_len=entry.prefixlen
        
        log_info(next_hop_ip)
        log_info(next_interface)
        return next_hop_ip,next_interface


class Router(object):
    def __init__(self, net: switchyard.llnetbase.LLNetBase):
        self.net = net
        self.arp_table=ARPTable(timeout=100)
        self.routing_table=RoutingTable()
        self.pending_arp_requests = []
        self.requests_ip=set()
        for interface in self.net.interfaces():
            self.routing_table.addEntry(interface.ipaddr, IPv4Address(interface.netmask), IPv4Address('0.0.0.0'), interface.name)
            print(f"Adding entry: {interface.ipaddr} {'255.255.255.0'}")
        table_file = open('forwarding_table.txt')
        try:
            for line in table_file:
                table_entry = line.split()
                self.routing_table.addEntry( IPv4Address(table_entry[0]), IPv4Address(table_entry[1]), IPv4Address(table_entry[2]), table_entry[3] )
        finally:
            table_file.close()
        # other initialization stuff here

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        timestamp, ifaceName, packet = recv
        # TODO: your logic here
        log_info(packet)
        self.arp_table.cleanup()

        if packet.has_header(Arp):
            eth = packet.get_header(Ethernet)
            if eth is None:
               return
         
            if eth.dst != "ff:ff:ff:ff:ff:ff" and eth.dst not in [iface.ethaddr for iface in self.net.interfaces()]:
               print("ARP:::Drop arp packet")
               return

            arp = packet.get_header(Arp)
            if arp is None:
               return

            self.arp_table.addEntry(arp.senderprotoaddr, arp.senderhwaddr)
            if arp.senderprotoaddr in self.requests_ip:
                self.requests_ip.remove(arp.senderprotoaddr)
        
            if arp.operation == ArpOperation.Request:  # ARP Request
               self.handle_arp_request(arp,packet)
            return
            
        if packet.has_header(IPv4):
            ip_packet = packet.get_header(IPv4)
            next_hop_ip,next_interface = self.routing_table.lookup(ip_packet.dst)
            if next_interface =='None':
                self.pending_arp_requests.remove(recv)
                return
            if ip_packet.ttl <= 0:
                print(f"IPv4:::Dropping packet with TTL=0 from {ip_packet.src}")
                return
            
            print(f"IPv4:::Received packet destined for {ip_packet.dst}")

            if ip_packet.dst in [interface.ipaddr for interface in self.net.interfaces()]:
                print(f"IPv4:::Packet destined for router itself, dropping packet: {ip_packet.dst}")
                return
            
            if str(next_hop_ip)=='0.0.0.0':
                next_hop_ip=ip_packet.dst
            if next_hop_ip in self.requests_ip:
                return
            if self.arp_table.get_macaddr(next_hop_ip) == None:
                self.requests_ip.add(next_hop_ip)
                print(f"IPv4:::No route found for {next_hop_ip}. This should trigger an ARP request if necessary.")
                next_hop_mac=self.wait_for_arp_reply(next_hop_ip,next_interface,self.net.interface_by_name(next_interface).ethaddr,self.net.interface_by_name(next_interface).ipaddr, recv)
            print(f"IPv4:::Found best route for ")
            self.forward_packet(packet,next_interface,next_hop_ip,recv)
            

    def handle_arp_request(self, arp, packet):
        target_ip = arp.targetprotoaddr
        for interface in self.net.interfaces():
            if interface.ipaddr == target_ip:
                sender_hwaddr = interface.ethaddr
                target_hwaddr = arp.senderhwaddr
                sender_protoaddr = interface.ipaddr
                target_protoaddr = arp.senderprotoaddr

                reply_packet = create_ip_arp_reply(sender_hwaddr, target_hwaddr, sender_protoaddr, target_protoaddr)
                print(f"Sending ARP reply: {sender_hwaddr} -> {target_hwaddr}")
                self.net.send_packet(interface, reply_packet)
                return
    
    def handle_arp_reply(self, arp,recv,target_ip):
        print(f"Received ARP reply: {arp.senderprotoaddr} is {arp.senderhwaddr}")
        self.arp_table.addEntry(arp.senderprotoaddr, arp.senderhwaddr)
        self.pending_arp_requests.remove(recv)
        self.requests_ip.remove(target_ip)
        return arp.senderhwaddr
   
    def wait_for_arp_reply(self, target_ip,interface,mac,ipaddr,recv,timeout=1.0):
        for i in range(5):
            if target_ip in self.requests_ip:
                self.net.send_packet(interface, create_ip_arp_request(mac, ipaddr, target_ip))
                time.sleep(1)
            start_time = time.time()
            while time.time() - start_time < timeout:
                try:
                    timestamp, ifaceName, packets = self.net.recv_packet(timeout=timeout)
                    arp=packets.get_header(Arp)
                    if arp:
                        arp_reply = self.handle_arp_reply(arp,recv,target_ip)
                        if arp_reply:
                            print(f"Received ARP reply for {target_ip}: {arp_reply}")
                            return arp_reply
                except NoPackets:
                    continue
        print(f"ARP request for {target_ip} failed ")
        return None
    def forward_packet(self,packet,interface_name,next_hop_ip,recv):
 
        interface = next((iface for iface in self.net.interfaces() if iface.name == interface_name), None)
        if not interface:
            print(f"Interface {interface_name} not found, cannot forward packet.")
            return
        
        ipv4 = packet.get_header(IPv4)
        eth = packet.get_header(Ethernet)
        log_info(next_hop_ip)
        next_hop_mac=self.arp_table.get_macaddr(next_hop_ip)
        ipv4.ttl = ipv4.ttl - 1
        eth.dst = next_hop_mac
        eth.src = interface.ethaddr
        del packet[IPv4] 
        del packet[Ethernet]
        packet.insert_header(0, ipv4)
        packet.insert_header(0, eth)
        if next_hop_mac ==None:
            return
        print(f"Forwarding packet to {next_hop_mac} on interface {interface_name}")
        if recv in self.pending_arp_requests:
            self.pending_arp_requests.remove(recv)
        self.net.send_packet(interface, packet)
        
   
    def start(self):
        '''A running daemon of the router.
        Receive packets until the end of time.
        '''
        while True:
            try:
                recv = self.net.recv_packet(timeout=1.0)  
            except NoPackets:
                continue
            except Shutdown:
                break
            if 'Arp' not in recv.packet.headers() and 'IPv4' not in recv.packet.headers():
                continue
            if 'Arp' in recv.packet.headers():
                print("have arp headher")
                self.handle_packet(recv)
            else :
                print("have IPv4 headher")
                self.pending_arp_requests.append(recv)
                
            cur=self.pending_arp_requests.copy()
            log_info(f"show cur_queue")
            log_info(cur)
            log_info(f"end showing queue")
            log_info(f"show requsts_ip")
            log_info(self.requests_ip)
            for request in cur:
                self.handle_packet(request)

        self.stop()

    def stop(self):
        self.net.shutdown()
    
    def print_ARPTable(self):
        print("Current arp table:")
        for ip,entry in self.arp_table.table.items():
            print(f"IP:{ip},MAC:{entry.macaddr},Timestamp:{entry.timestamp}")
          


def main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    router = Router(net)
    router.start()
