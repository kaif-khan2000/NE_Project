
from Crypto.PublicKey import RSA
import netifaces
from base64 import b64encode, b64decode
from Crypto.Cipher import PKCS1_OAEP
import socket

import hashlib


interface_no = 2

def get_ipv4_address():
    interfaces = netifaces.interfaces()
    ipv4_address = None
    addrs = netifaces.ifaddresses(interfaces[interface_no])
    if netifaces.AF_INET in addrs:
        ipv4_address = addrs[netifaces.AF_INET][0]['addr']
    
    if ipv4_address is not None:
        return ipv4_address
    else:
        return None

def get_pubKey_from_str(pubKeyStr):
    return RSA.importKey(pubKeyStr)

def decrypt_message(msg, key):
    cipher = PKCS1_OAEP.new(key)
    msg = cipher.decrypt(msg)
    return b64decode(msg).decode('utf-8')

def queryDNS():
    return '843b5b76c577498dfc9fccd4ef55236c5f9d8c7f1389ca5ff019b6a056deeaaf', get_ipv4_address(), ''


def get_host_ipv6():
    # create a UDP socket
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # define the broadcast address and port
    ipv4_Address = get_ipv4_address()
    port = 9990

    hostId, sendAddress, pubKey = queryDNS()
    # create a message to send
    challenge = 'challenge'
    message = hostId + " " + challenge
    # send the message
    udp_socket.sendto(message.encode('utf-8'), (sendAddress, port))

    # receive the response
    response, address = udp_socket.recvfrom(1024)
    response = response.decode('utf-8')
    print(response)

get_host_ipv6()