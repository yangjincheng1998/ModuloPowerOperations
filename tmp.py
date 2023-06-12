import socket
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

def generate_dh_key(parameters):
    private_key = parameters.generate_private_key()
    peer_public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_key, peer_public_key

def receive_data_length(client_socket):
    data_length = client_socket.recv(4)
    return int.from_bytes(data_length, 'big')

def receive_data(server_socket, buffer_size):
    data = server_socket.recv(buffer_size)
    return data

def send_data(client_socket, data):
    data_length = len(data).to_bytes(4, 'big')
    client_socket.sendall(data_length)
    client_socket.sendall(data)

def start_client():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 12345))

    start_request = 'START'
    client_socket.send(start_request.encode())

    ack_message = receive_data(client_socket, 4)  # Receive ACK message
    print('Received ACK:', ack_message.decode())

    parameters_pem = receive_data(client_socket, receive_data_length(client_socket))
    parameters = serialization.load_pem_parameters(parameters_pem, backend=default_backend())

    server_public_key_pem = receive_data(client_socket, receive_data_length(client_socket))
    server_public_key = serialization.load_pem_public_key(server_public_key_pem, backend=default_backend())

    private_key, peer_public_key = generate_dh_key(parameters)

    send_data(client_socket, peer_public_key)

    shared_key = private_key.exchange(server_public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
        backend=default_backend()
    ).derive(shared_key)

    while True:
        data_to_send = input('Please input the data to send: ')
        data_to_send += ' ' * ((16 - len(data_to_send) % 16) % 16)

        cipher = Cipher(algorithms.AES(derived_key), modes.ECB(), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(data_to_send.encode())

        send_data(client_socket, encrypted_data)

        encrypted_data = receive_data(client_socket, receive_data_length(client_socket))
        cipher = Cipher(algorithms.AES(derived_key), modes.ECB(), backend=default_backend())
        decryptor = cipher.decryptor()
        data = decryptor.update(encrypted_data)
        print('Received from server:', data.decode().rstrip())

    client_socket.close()


if __name__ == "__main__":
    start_client()
