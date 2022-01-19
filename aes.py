from base64 import encode
import os
import csv
import random
import datetime
from string import ascii_letters, digits
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


message_sizes = [128, 320, 512, 1024, 2048]


def generate_message(message_size):
    message = ''.join(random.choice(ascii_letters + digits) for i in range(message_size))
    return message


def encrypt_message(key, message, auth_code):
    iv = os.urandom(12)

    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend(),
    ).encryptor()

    encryptor.authenticate_additional_data(auth_code)
    encrypted_message = encryptor.update(message) + encryptor.finalize()

    return(iv, encrypted_message, encryptor.tag)


def decrypt_message(key, auth_code, iv, encrypted_message, encryptor_tag):
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, encryptor_tag),
        backend=default_backend(),
    ).decryptor()

    decryptor.authenticate_additional_data(auth_code)

    return decryptor.update(encrypted_message) + decryptor.finalize()


def create_csv_file(filename, results):
    with open(filename, 'w') as csv_file:
        writer = csv.writer(csv_file, delimiter=';', quotechar='|', quoting=csv.QUOTE_MINIMAL)
        for result in results:
            writer.writerow(list(result.values()))

    print(f'{filename} finished!')


def encryption_tests(key):
    auth_code = 'encrypt_authenticator'

    for size in message_sizes:
        results = []

        for i in range(5001):
            message = generate_message(size)

            # Encrypting
            start = datetime.datetime.now()
            iv, encrypted_message, encryptor_tag = encrypt_message(key.encode(), message.encode(), auth_code.encode())
            end = datetime.datetime.now()
            encryption_time = (end - start).total_seconds() * 1000

            # Decrypting
            start = datetime.datetime.now()
            decrypt_message(key.encode(), auth_code.encode(), iv, encrypted_message, encryptor_tag)
            end = datetime.datetime.now()
            decryption_time = (end - start).total_seconds() * 1000

            results.append({'id': i+1, 'encryption_time': encryption_time, 'decryption_time': decryption_time})
            
        create_csv_file(f'aes-{str(len(key))}-{str(size)}.csv', results)


def main():
    encryption_tests('0123456789ABCDEF')
    encryption_tests('0123456789ABCDEFGHIJKLMNOPQRSTUV')


if __name__ == '__main__':
    main()
