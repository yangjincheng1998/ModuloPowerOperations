# 导入所需的库
import socket
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
import json

def generate_dh_key():
    # 生成Diffie-Hellman（DH）参数和密钥对
    parameters = dh.generate_parameters(generator=2, key_size=512, backend=default_backend())
    private_key = parameters.generate_private_key()
    # 将公钥序列化为PEM格式
    peer_public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    # 将DH参数序列化为PEM格式
    parameters_pem = parameters.parameter_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.ParameterFormat.PKCS3
    )
    return parameters, parameters_pem, private_key, peer_public_key

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

def start_server():
    # 创建服务器套接字，绑定地址和端口，并开始监听
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 12345))
    server_socket.listen(5)

    print('开启服务器，服务器监听客户端')
    while True:
        # 接受客户端的连接
        client_socket, addr = server_socket.accept()
        print('与客户端建立连接，客户端地址为：', addr)

        # 接收并打印客户端的请求
        start_request = receive_data(client_socket).decode()
        print('收到客户端外包开始请求:', start_request)

        # 发送确认消息给客户端
        ack_message = 'ACK'
        send_data(client_socket, ack_message.encode())

        # 生成Diffie-Hellman（DH）参数和密钥对，然后发送给客户端
        parameters, parameters_pem, dh_private_key, peer_public_key = generate_dh_key()
        send_data(client_socket, parameters_pem)
        send_data(client_socket, peer_public_key)

        # 接收客户端的公钥，并将其从PEM格式反序列化为公钥对象
        client_public_key_pem = receive_data(client_socket)
        client_public_key = serialization.load_pem_public_key(client_public_key_pem, backend=default_backend())

        # 使用客户端的公钥和服务器的私钥进行密钥交换，生成共享密钥
        shared_key = dh_private_key.exchange(client_public_key)

        print("DH共享密钥协商成功")
        # 使用HKDF函数从共享密钥派生出一个新的密钥
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
            backend=default_backend()
        ).derive(shared_key)

        # 接收并解析RSA公钥和私钥的JSON
        rsa_keys_json = receive_data(client_socket).decode()
        rsa_keys = json.loads(rsa_keys_json)

        # 从JSON中获取公钥和私钥的PEM字符串
        private_pem = rsa_keys['private_key']
        public_pem = rsa_keys['public_key']

        # 将公钥和私钥的PEM字符串反序列化为公钥和私钥对象
        rsa_private_key = serialization.load_pem_private_key(
            private_pem.encode(),
            password=None,
            backend=default_backend()
        )

        rsa_public_key = serialization.load_pem_public_key(
            public_pem.encode(),
            backend=default_backend()
        )

        # 打印公钥和私钥
        print('收到的来自客户端的私钥为：', private_pem)
        print('收到的来自客户端的公钥为：', public_pem)

        while True:
            # 接收客户端的请求类型
            header = receive_data(client_socket).decode()
            if header not in ['ENCRYPT', 'DECRYPT']:
                print('无效的头部字段，期望"ENCRYPT"或"DECRYPT"，但是收到了', header)
                continue

            # 创建AES加密器和解密器
            cipher = Cipher(algorithms.AES(derived_key), modes.ECB(), backend=default_backend())
            encryptor = cipher.encryptor()
            decryptor = cipher.decryptor()

            # 接收并解密客户端发送的AES加密数据
            aes_encrypted_data = receive_data(client_socket, 4)
            aes_decrypted_data = decryptor.update(aes_encrypted_data)

            if header == 'ENCRYPT':
                try:
                    print('收到的来自客户端的消息:', aes_decrypted_data.decode().rstrip())
                except UnicodeDecodeError:
                    print('收到的来自客户端的消息:', aes_decrypted_data)
                # 使用客户端的公钥对明文进行RSA加密
                rsa_encrypted_reply = rsa_public_key.encrypt(
                    aes_decrypted_data,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                # 将二进制数据转换成十六进制字符串
                rsa_encrypted_reply_hex = rsa_encrypted_reply.hex()

                print('服务器模幂外包加密明文后的密文为:', rsa_encrypted_reply_hex)
                # 使用DH的共享密钥对RSA加密后的密文进行AES加密
                aes_encrypted_reply = encryptor.update(rsa_encrypted_reply)

                # 发送AES加密后的密文给客户端
                send_data(client_socket, aes_encrypted_reply)
            else:
                # 将AES解密后的数据转换为十六进制字符串
                decrypted_data_hex = aes_decrypted_data.hex()
                try:
                    print('收到的来自客户端的消息:', decrypted_data_hex)
                except UnicodeDecodeError:
                    print('收到的来自客户端的消息:', decrypted_data_hex)

                # 使用服务器的私钥对AES解密后的数据进行RSA解密
                rsa_decrypted_reply = rsa_private_key.decrypt(
                    aes_decrypted_data,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )

                try:
                    print('服务器模幂外包解密明文后的明文为:', rsa_decrypted_reply.decode().rstrip())
                except UnicodeDecodeError:
                    print('服务器模幂外包解密明文后的明文为:', rsa_decrypted_reply)

                # 对解密后的明文进行填充，然后进行AES加密
                rsa_decrypted_reply += b' ' * ((16 - len(rsa_decrypted_reply) % 16) % 16)

                aes_encrypted_reply = encryptor.update(rsa_decrypted_reply)
                # 发送AES加密后的密文给客户端
                send_data(client_socket, aes_encrypted_reply)

        # 关闭客户端套接字
        client_socket.close()

if __name__ == "__main__":
    # 如果直接运行这个文件，那么启动服务器
    start_server()


