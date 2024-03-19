import os
import random
import string
import timeit
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding



# (A) - > Produzir todos os ficheiros com os diferentes tamanhos

# Sizes in bytes

file_sizes_aes = [8, 64, 512, 4096, 32768, 262144, 2097152]
file_sizes_sha = [8, 64, 512, 4096, 32768, 262144, 2097152]
file_sizes_rsa = [2, 4, 8, 16, 32, 64, 128]

 

def generate_random_text_file(size_bytes):
    return os.urandom(size_bytes)

# Generate random text files for aes
def generate_aes_files(file_sizes_aes): 
    for size in file_sizes_aes:
        with open(f"aes_{size}.txt", "wb") as f:
            f.write(generate_random_text_file(size))

# Generate random text files for sha
def generate_sha_files(files_sizes_sha):
    for size in file_sizes_sha:
        with open(f"sha_{size}.txt", "wb") as f:
            f.write(generate_random_text_file(size))

# Generate random text files for rsa
def generate_rsa_files(files_sizes_rsa):
    for size in file_sizes_rsa:
        with open(f"rsa{size}.txt", "wb") as f:
            f.write(generate_random_text_file(size))

# (B) -> Funcões de encriptacao e desencriptacao. 
# Têm como argumentos o ficheiros de input e de output 
        
generate_aes_files(file_sizes_aes)
generate_sha_files(file_sizes_sha)
generate_rsa_files(file_sizes_rsa)

def encrypt_file_aes(input_file, output_file, key):
    with open(input_file, 'rb') as f:
        plaintext = f.read()
    padded_plaintext = pad(plaintext, algorithms.AES.block_size)
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_plaintext) + encryptor.finalize()
    with open(output_file, 'wb') as f:
        f.write(encrypted_data)

def decrypt_file_aes(input_file, key):
    with open(input_file, 'rb') as f:
        encrypted_data = f.read()
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    # Não é preciso retornar ou modificar o ficheiro. 



def pad(data, block_size):
    padding_length = block_size - (len(data) % block_size)
    return data + bytes([padding_length] * padding_length)




# Key for AES encryption and decryption (256-bit key)
key = os.urandom(32) 


# Encrypt and decrypt each file size
def Measure_Time_AES(file_sizes_aes):
    # Initialize dictionaries to hold lists of times for each file size
    encryption_times = {size: [] for size in file_sizes_aes}
    decryption_times = {size: [] for size in file_sizes_aes}
    num_runs = 10
    key = os.urandom(32)
    for i in range(num_runs):
        print(f"Iteration {i+1}:")
        for size in file_sizes_aes:
            input_file = f"aes_{size}.txt"
            encrypted_file = f"aes_{size}_encrypted.txt"
            
            # Measure encryption time
            encryption_time = timeit.timeit(lambda: encrypt_file_aes(input_file, encrypted_file, key), number=1)
            encryption_times[size].append(encryption_time)
            
            # Measure decryption time
            decryption_time = timeit.timeit(lambda: decrypt_file_aes(encrypted_file, key), number=1)
            decryption_times[size].append(decryption_time)
            
            # Print the times for the current iteration
            print(f"File Size: {size} bytes, Encryption Time: {encryption_time:.6f} seconds, Decryption Time: {decryption_time:.6f} seconds")

    # If you want to print a summary after all iterations
    print("\nSummary of Encryption Times:")
    for size in file_sizes_aes:
        print(f"File Size: {size} bytes, Encryption Times: {encryption_times[size]}")

    print("\nSummary of Decryption Times:")
    for size in file_sizes_aes:
        print(f"File Size: {size} bytes, Decryption Times: {decryption_times[size]}")

# Adjust variables `file_sizes_aes` and `key` as per your setup
Measure_Time_AES(file_sizes_aes)


def measure_time_for_random_files(file_size):
    encryption_times = []
    decryption_times = []
    num_iterations = 10
    for _ in range(num_iterations):
        # Generate a new file with random content for each iteration
        random_data = os.urandom(file_size)
        input_file = f"temp_{file_size}.txt"
        encrypted_file = f"temp_{file_size}_encrypted.txt"

        with open(input_file, 'wb') as f:
            f.write(random_data)
        
        # Measure encryption time
        start_time = timeit.default_timer()
        encrypt_file_aes(input_file, encrypted_file, key)
        encryption_times.append(timeit.default_timer() - start_time)
        
        # Measure decryption time
        start_time = timeit.default_timer()
        decrypt_file_aes(encrypted_file, key)
        decryption_times.append(timeit.default_timer() - start_time)
        
        # Cleanup
        os.remove(input_file)
        os.remove(encrypted_file)
    
    # Print results for this file size
    print(f"File Size: {file_size} bytes")
    for i in range(num_iterations):
        print(f"Iteration {i+1}: Encryption Time: {encryption_times[i]:.6f} seconds, Decryption Time: {decryption_times[i]:.6f} seconds")
    print()

# Example usage
file_sizes_aes = [8, 64, 512, 4096, 32768, 262144, 2097152]
key = os.urandom(32) # AES key

for size in file_sizes_aes:
    measure_time_for_random_files(size)


def generate_rsa_keys(): 
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

# Encrypt data using RSA public key
def rsa_encrypt(public_key, data):
    encrypted = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted

# Decrypt data using RSA private key
def rsa_decrypt(private_key, encrypted_data):
    decrypted = private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted

# Measure RSA encryption and decryption times for various file sizes
def measure_rsa_performance(file_sizes_rsa):
    private_key, public_key = generate_rsa_keys()
    for size in file_sizes_rsa:
        data = os.urandom(size)
        
        # Measure encryption time
        encryption_time = timeit.timeit(lambda: rsa_encrypt(public_key, data), number=10) / 10
        
        # Encrypt the data for decryption measurement
        encrypted_data = rsa_encrypt(public_key, data)
        
        # Measure decryption time
        decryption_time = timeit.timeit(lambda: rsa_decrypt(private_key, encrypted_data), number=10) / 10
        
        print(f"File size: {size} bytes, Encryption time: {encryption_time:.6f} seconds, Decryption time: {decryption_time:.6f} seconds")

# Define the file sizes for RSA

print("Tempo de Encriptacao e Decriptacao do algoritmo RSA")
# Measure and print RSA performance
measure_rsa_performance(file_sizes_rsa)

# Function to generate a SHA-256 hash of the data
def sha256_hash(data):
    sha256 = hashlib.sha256()
    sha256.update(data)
    return sha256.hexdigest()

# Measure the time for SHA-256 hash generation for various file sizes
def measure_sha256_performance(file_sizes_sha):
    for size in file_sizes_sha:
        data = os.urandom(size)
        
        # Measure hash generation time
        hash_time = timeit.timeit(lambda: sha256_hash(data), number=10) / 10
        
        print(f"File size: {size} bytes, SHA-256 hash generation time: {hash_time:.6f} seconds")

print("SHA digests generation times")

# Measure and print SHA-256 performance
measure_sha256_performance(file_sizes_sha)
