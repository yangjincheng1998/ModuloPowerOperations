import socket
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
import json

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

def receive_data(client_socket, buffer_size=1024):
    # 接收来自客户端的数据，首先接收4个字节的数据长度
    data_length = int.from_bytes(client_socket.recv(4), 'big')
    data = b''
    while len(data) < data_length:
        # 循环接收数据，直到读取到的数据长度与发送的数据长度匹配
        more_data = client_socket.recv(min(data_length - len(data), buffer_size))
        if not more_data:
            # 如果没有更多的数据，就抛出异常
            raise Exception('Failed to receive all data')
        data += more_data
    return data

def send_data(client_socket, data):
    # 向客户端发送数据，首先发送4个字节的数据长度
    data_length = len(data).to_bytes(4, 'big')
    client_socket.sendall(data_length)
    client_socket.sendall(data)


def start_client():
    # 创建一个新的套接字，并连接到服务器
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 12345))

    # 发送一个启动请求给服务器
    start_request = 'START'
    send_data(client_socket, start_request.encode())

    # 接收服务器的响应，应为'ACK'
    ack_message = receive_data(client_socket)
    print('收到来自服务器的外包请求响应:', ack_message.decode())

    # 接收服务器发送的Diffie-Hellman参数
    parameters_pem = receive_data(client_socket)
    parameters = serialization.load_pem_parameters(parameters_pem, backend=default_backend())

    # 接收服务器发送的Diffie-Hellman公钥
    server_public_key_pem = receive_data(client_socket)
    server_public_key = serialization.load_pem_public_key(server_public_key_pem, backend=default_backend())

    # 使用收到的参数生成新的Diffie-Hellman私钥和公钥
    dh_private_key, peer_public_key = generate_dh_key(parameters)

    # 将公钥发送给服务器
    send_data(client_socket, peer_public_key)

    # 使用服务器的公钥和自己的私钥生成共享密钥
    shared_key = dh_private_key.exchange(server_public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
        backend=default_backend()
    ).derive(shared_key)

    print("DH共享密钥协商成功")

    # 生成RSA公钥和私钥
    rsa_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    rsa_public_key = rsa_private_key.public_key()

    # 将公钥和私钥序列化为PEM格式的字符串
    private_pem = rsa_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')

    public_pem = rsa_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    # 将公钥和私钥的PEM字符串打包成JSON发送给服务器
    rsa_keys = {
        'private_key': private_pem,
        'public_key': public_pem,
    }
    rsa_keys_json = json.dumps(rsa_keys)

    # 发送RSA公钥和私钥的JSON
    send_data(client_socket, rsa_keys_json.encode())

    # 循环，让用户输入要进行的操作，可以选择加密或解密
    while True:
        operation = input('请输入您想要进行的操作（1.加密或2.解密）: ')
        if operation.lower() not in ['1', '2']:
            print('无效的操作，请输入"1"或"2"')
            continue
        if operation.lower() == '1':
            header = 'ENCRYPT'
        else:
            header = 'DECRYPT'

        # 将用户选择的操作（加密或解密）发送给服务器
        send_data(client_socket, header.encode())

        # 如果用户选择的是加密操作
        if header == 'ENCRYPT':
            # 获取用户输入的待加密数据
            data_to_send = input('请输入待加密或解密的数据: ')
            # 为了满足AES加密的要求，需要确保待加密数据的长度是16的倍数
            data_to_send += ' ' * ((16 - len(data_to_send) % 16) % 16)

            # 使用AES对用户输入的数据进行加密
            cipher = Cipher(algorithms.AES(derived_key), modes.ECB(), backend=default_backend())
            encryptor = cipher.encryptor()
            encrypted_data = encryptor.update(data_to_send.encode())

            # 将加密后的数据发送给服务器
            send_data(client_socket, encrypted_data)

            # 接收服务器返回的加密数据
            encrypted_data = receive_data(client_socket)

            # 使用AES对接收到的数据进行解密，得到原始数据
            cipher = Cipher(algorithms.AES(derived_key), modes.ECB(), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_data = decryptor.update(encrypted_data)

            # 打印出来自服务器的加密数据
            print('收到来自服务器端的外包计算得到密文:', decrypted_data.hex())

            # 使用RSA私钥对数据进行解密
            rsa_decrypted_data = rsa_private_key.decrypt(
                decrypted_data,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            # 打印RSA解密后的数据
            print('客户端本地验证是否相等:', rsa_decrypted_data.decode())

        # 如果用户选择的是解密操作
        else:
            # 如果存在需要解密的数据
            if decrypted_data is not None:
                # 确保待解密数据的长度是16的倍数
                decrypted_data += b' ' * ((16 - len(decrypted_data) % 16) % 16)

                # 使用AES对数据进行加密
                cipher = Cipher(algorithms.AES(derived_key), modes.ECB(), backend=default_backend())
                encryptor = cipher.encryptor()
                encrypted_data = encryptor.update(decrypted_data)

                # 将加密后的数据发送给服务器
                send_data(client_socket, encrypted_data)

                # 接收服务器返回的加密数据
                encrypted_data = receive_data(client_socket)

                # 使用AES对接收到的数据进行解密，得到原始数据
                cipher = Cipher(algorithms.AES(derived_key), modes.ECB(), backend=default_backend())
                decryptor = cipher.decryptor()
                data = decryptor.update(encrypted_data)

                # 打印出来自服务器的解密数据
                try:
                    print('收到来自服务器端的外包计算得到明文:', data.decode().rstrip())
                except UnicodeDecodeError:
                    print('收到来自服务器端的外包计算得到明文:', data)
            else:
                print("找不到待解密的密文")

    # 关闭客户端套接字
    client_socket.close()


if __name__ == "__main__":
    start_client()
