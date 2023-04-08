# generate key pair

from Crypto.PublicKey import RSA
import netifaces
from base64 import b64encode, b64decode
from Crypto.Cipher import PKCS1_OAEP
import socket

import hashlib

interface_no = 2
def generate_key_pair():
    key = RSA.generate(2048)

    # save key pair
    with open('key.pem', 'wb') as f:
        f.write(key.exportKey(format='PEM'))

def encrypt_message(msg, key):
    msg = b64encode(msg.encode('utf-8'))
    cipher = PKCS1_OAEP.new(key)
    return cipher.encrypt(msg)

def decrypt_message(msg, key):
    cipher = PKCS1_OAEP.new(key)
    msg = cipher.decrypt(msg)
    return b64decode(msg).decode('utf-8')

def get_pubKey_from_str(pubKeyStr):

    return RSA.importKey(pubKeyStr)


def get_ipv6_address():
    # Get a list of all network interfaces
    interfaces = netifaces.interfaces()
    # Find the first interface that has an IPv6 address
    ipv6_address = None
    addrs = netifaces.ifaddresses(interfaces[interface_no])
    if netifaces.AF_INET6 in addrs:
        ipv6_address = addrs[netifaces.AF_INET6][0]['addr']
    
    if ipv6_address is not None:
        return ipv6_address
    else:
        return None

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

def get_broadcast_address():
    interfaces = netifaces.interfaces()
    broadcast_address = None
    addrs = netifaces.ifaddresses(interfaces[interface_no])
    if netifaces.AF_INET in addrs:
        broadcast_address = addrs[netifaces.AF_INET][0]['broadcast']
    
    if broadcast_address is not None:
        return broadcast_address
    else:
        return None

def getsysinfo():
    # get the ip address from the system
    ipv6_address = get_ipv6_address()
    if ipv6_address is None:
        print('No IPv6 address found')
        return
    ipv6_address2 = ""
    private_key = ""
    public_key = ""
    key = ""
    # get ip address from the file
    with open('ip.txt', 'r') as f:
        ipv6_address2 = f.read()
        print(ipv6_address2)

    # check if the ip address is the same
    if ipv6_address == ipv6_address2:
        # get the public key from the file
        with open('key.pem', 'r') as f:
            key_data = f.read()
            print(key_data)
            # key = RSA.importKey(key_data)
            key = RSA.importKey(key_data)
            
            public_key = key.public_key()
    else:
        # generate key pair
        generate_key_pair()
        # write ip address to the file
        with open('ip.txt', 'w') as f:
            f.write(ipv6_address)
        # get the public key from the file
        with open('key.pem', 'r') as f:
            key = RSA.importKey(b64decode(f.read()))
            public_key = key.public_key()

    print('IPv6 address: ', ipv6_address)

    return ipv6_address, public_key, key

def get_hostId(publicKey):
    publicStr = publicKey.exportKey(format='PEM')
    sha256 = hashlib.sha256()
    sha256.update(publicStr)
    hostId = sha256.hexdigest()
    return hostId

def udp_listener():
    ipv6_address, public_key, key = getsysinfo()
    ipv4_address = get_ipv4_address()
    hostId = get_hostId(public_key)
    broadcast_address = get_broadcast_address()
    print("broadcast_address:",broadcast_address)
    print("hostId:",hostId)
    print(ipv4_address)
    # create a UDP socket
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    # bind the socket to a specific address and port
    # udp_socket.bind((ipv4_address, 9999))
    udp_socket.bind((broadcast_address, 9999))

    print('UDP server listening on port 9999...')

    while True:
        # receive data from a client
        data, addr = udp_socket.recvfrom(1024)
        msg = data.decode('utf-8')
        msg = msg.split(" ")
        print(f"Received {len(data)} bytes from {addr}")
        print(f"Data: {msg}")
        if msg[0] == hostId:
            response = f"{ipv6_address}"
            udp_socket.sendto(response.encode('utf-8'), (msg[2],int(msg[3])))
            print("hostId matched")
        else :
            print("hostId not matched")
        # send a response back to the client


if __name__ == '__main__':
    udp_listener()