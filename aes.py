import csv
import random
import datetime
from string import ascii_letters
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


message_sizes = [128, 320, 512, 1024, 2048]


def generate_message(message_size):
    message = ''.join(random.choice(ascii_letters) for i in range(message_size))
    return message

print(f'{generate_message(120)}')
