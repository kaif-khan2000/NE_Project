import socket
import netifaces

interface_no = 2

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

def broadcast_message(message, from_addr):
    # create a UDP socket
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # set the socket to allow broadcasting
    udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    # define the broadcast address and port
    broadcast_address = get_broadcast_address()
    broadcast_port = 9999

    # create a message to broadcast
    message = message + " " + from_addr[0] + " " + str(from_addr[1])
    # send the message as a broadcast to the address and port
    udp_socket.sendto(message.encode(), (broadcast_address, broadcast_port))

    # close the socket
    udp_socket.close()

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


def udp_server():
    # create a UDP socket
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ipv4_Address = get_ipv4_address()
    # bind the socket to a specific address and port
    udp_socket.bind((ipv4_Address, 9990))

    print('UDP server listening on port 9990...')

    while True:
        # receive data from a client
        data, addr = udp_socket.recvfrom(1024)
        msg = data.decode('utf-8')
        msg2 = msg.split(" ")
        print(f"Received {len(data)} bytes from {addr}")
        print(f"Data: {msg}")
        
        broadcast_message(msg, addr)

udp_server()