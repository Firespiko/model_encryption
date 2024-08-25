
"""
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os

class ModelEncryptorDecryptor:
    def __init__(self):
        self.key = None
        self.iv = None

    def generate_key_iv(self):
        self.key = os.urandom(32)  # AES-256 requires a 32-byte key
        self.iv = os.urandom(16)   # AES block size is 16 bytes

    def load_key_iv(self, key_path='key.bin', iv_path='iv.bin'):
        with open(key_path, 'rb') as key_file:
            self.key = key_file.read()
        with open(iv_path, 'rb') as iv_file:
            self.iv = iv_file.read()

    def aes_encrypt(self, data):
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(self.iv), backend=default_backend())
        encryptor = cipher.encryptor()

        # Pad the data to be a multiple of the block size
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()

        # Encrypt the padded data
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        return encrypted_data

    def aes_decrypt(self, encrypted_data):
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(self.iv), backend=default_backend())
        decryptor = cipher.decryptor()

        # Decrypt the data
        decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

        # Unpad the decrypted data
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        data = unpadder.update(decrypted_padded_data) + unpadder.finalize()
        return data

    def encrypt_file(self, input_file_path, output_file_path):
        with open(input_file_path, 'rb') as file:
            data = file.read()

        encrypted_data = self.aes_encrypt(data)

        with open(output_file_path, 'wb') as file:
            file.write(encrypted_data)

        self.save_key_iv()

    def decrypt_file(self, input_file_path, output_file_path):
        with open(input_file_path, 'rb') as file:
            encrypted_data = file.read()

        data = self.aes_decrypt(encrypted_data)

        with open(output_file_path, 'wb') as file:
            file.write(data)

    def save_key_iv(self, key_path='key.bin', iv_path='iv.bin'):
        with open(key_path, 'wb') as key_file:
            key_file.write(self.key)
        with open(iv_path, 'wb') as iv_file:
            iv_file.write(self.iv)

    def encrypt(self, input_file_path, output_file_path):
        self.generate_key_iv()
        self.encrypt_file(input_file_path, output_file_path)
        print(f'Encrypted file saved as {output_file_path}')
        print(f'Key saved as key.bin')
        print(f'IV saved as iv.bin')

    def decrypt(self, input_file_path, output_file_path):
        self.load_key_iv()
        self.decrypt_file(input_file_path, output_file_path)
        print(f'Decrypted file saved as {output_file_path}')

if __name__ == '__main__':
    encryptor_decryptor = ModelEncryptorDecryptor()

    # Encrypt
    input_file_path = 'model.onnx'      # Path to the original ONNX model file
    output_file_path = 'model.onnx.enc' # Path to save the encrypted model file
    encryptor_decryptor.encrypt(input_file_path, output_file_path)

    # Decrypt
    input_encrypted_file_path = 'model.onnx.enc'  # Path to the encrypted ONNX model file
    output_decrypted_file_path = 'model_decrypted.onnx'  # Path to save the decrypted model file
    encryptor_decryptor.decrypt(input_encrypted_file_path, output_decrypted_file_path)
        """
        
from flask import Flask, request, jsonify, send_file
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os
import boto3

app = Flask(__name__)

# Setup your S3 client if using AWS S3
# s3 = boto3.client('s3')

class ModelEncryptorDecryptor:
    def __init__(self):
        self.key = None
        self.iv = None

    def generate_key_iv(self):
        self.key = os.urandom(32)  # AES-256 requires a 32-byte key
        self.iv = os.urandom(16)   # AES block size is 16 bytes

    def aes_encrypt(self, data):
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(self.iv), backend=default_backend())
        encryptor = cipher.encryptor()

        # Pad the data to be a multiple of the block size
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()

        # Encrypt the padded data
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        return encrypted_data

    def save_key_iv(self, model_name):
        key_path = f'{model_name}_key.bin'
        iv_path = f'{model_name}_iv.bin'
        with open(key_path, 'wb') as key_file:
            key_file.write(self.key)
        with open(iv_path, 'wb') as iv_file:
            iv_file.write(self.iv)
        return key_path, iv_path

    def encrypt_model(self, model_path, encrypted_model_path):
        self.generate_key_iv()
        with open(model_path, 'rb') as file:
            data = file.read()
        encrypted_data = self.aes_encrypt(data)
        with open(encrypted_model_path, 'wb') as file:
            file.write(encrypted_data)
        return encrypted_model_path


@app.route('/encrypt-model', methods=['POST'])
def encrypt_model():
    model_name = request.form['model_name']
    model_path = f'models/{model_name}.onnx'
    encrypted_model_path = f'models/{model_name}.onnx.enc'

    # Initialize the encryptor
    encryptor_decryptor = ModelEncryptorDecryptor()
    encrypted_model_path = encryptor_decryptor.encrypt_model(model_path, encrypted_model_path)
    
    # Save the key and IV
    key_path, iv_path = encryptor_decryptor.save_key_iv(model_name)

    # Optionally, upload the encrypted model to S3
    # s3.upload_file(encrypted_model_path, 'your-bucket-name', encrypted_model_path)

    return jsonify({
        'status': 'success',
        'encrypted_model_path': encrypted_model_path,
        'key_path': key_path,
        'iv_path': iv_path
    })

@app.route('/get-encrypted-model/<model_name>', methods=['GET'])
def get_encrypted_model(model_name):
    encrypted_model_path = f'models/{model_name}.onnx.enc'
    key_path = f'{model_name}_key.bin'
    iv_path = f'{model_name}_iv.bin'

    # Return the encrypted model, key, and IV
    # Optionally, you could implement additional security checks here
    return jsonify({
        'encrypted_model_url': f'/download-file/{encrypted_model_path}',
        'key_url': f'/download-file/{key_path}',
        'iv_url': f'/download-file/{iv_path}'
    })

@app.route('/download-file/<path:filename>', methods=['GET'])
def download_file(filename):
    return send_file(filename, as_attachment=True)

if __name__ == '__main__':
    os.makedirs('models', exist_ok=True)
    app.run(debug=True)
