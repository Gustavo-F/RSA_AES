import csv
import random
import datetime
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP
from string import ascii_letters, digits


message_sizes = [128, 320, 512, 1024, 2048]


def generate_keys(key_size):
    key_pair = RSA.generate(key_size)
    public_key = key_pair.publickey()

    return(key_pair, public_key)


def encrypt_message(public_key, message):
    encryptor = PKCS1_OAEP.new(public_key)
    encrypted_message = encryptor.encrypt(message.encode())

    return encrypted_message


def decrypt_message(key_pair, encrypted_message):
    decryptor = PKCS1_OAEP.new(key_pair)
    decrypted_message = decryptor.decrypt(encrypted_message)

    return decrypted_message


def generate_message(message_size):
    message = ''.join(random.choice(ascii_letters + digits) for i in range(message_size))

    return message


def create_csv_file(filename, results):
    with open(filename, 'w') as csv_file:
        writer = csv.writer(csv_file, delimiter=';', quotechar='|', quoting=csv.QUOTE_MINIMAL)
        for result in results:
            writer.writerow(list(result.values()))

    print(f'{filename} finished!')


def encryption_tests(key_size):
    max_size = 86 if key_size == 1024 else 342 if key_size == 4096 else 0
    key_pair, public_key = generate_keys(key_size)
    
    for message_size in message_sizes:
        results = []

        for i in range(5001):
            message = generate_message(message_size)

            if len(message) <= max_size:
                
                # Encryption
                start = datetime.datetime.now()
                encrypted_message = encrypt_message(public_key, message)
                end = datetime.datetime.now()
                encryption_time = (end - start).total_seconds() * 1000

                # Decryption
                start = datetime.datetime.now()
                decrypted_message = decrypt_message(key_pair, encrypted_message)
                end = datetime.datetime.now()
                decryption_time = (end - start).total_seconds() * 1000

            else:
                splited_messages = [message[j:j+max_size] for j in range(0, len(message), max_size)]
                
                # Encryption
                start = datetime.datetime.now()
                for index, message in enumerate(splited_messages):
                    splited_messages[index] = encrypt_message(public_key, message)
                end = datetime.datetime.now()
                encryption_time = (end - start).total_seconds() * 1000

                # Decryption
                start = datetime.datetime.now()
                for encrypted_message in splited_messages:
                    decrypt_message(key_pair, encrypted_message)
                end = datetime.datetime.now()
                decryption_time = (end - start).total_seconds() * 1000

            results.append({'id': i + 1, 'encrypt_time': encryption_time, 'decryption_time': decryption_time})
        
        create_csv_file(f'rsa-{str(key_size)}-{str(message_size)}.csv', results)


def main():    
    encryption_tests(1024)
    encryption_tests(4096)


if __name__ == '__main__':
    main()
