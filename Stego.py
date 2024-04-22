import cv2
import numpy as np


def string_to_bin(message):
    binary_message = ""
    for char in message:
        # Convert each character to its 8-bit binary representation
        binary_char = bin(ord(char))[2:].zfill(8)  # Pad with zeros to 8 bits
        binary_message += binary_char
    # Append end-of-message marker (8 consecutive 0s)
    binary_message += '00000000'
    return binary_message

def embed_bit(channel, bit):
    # Embeds the bit into the channel by modifying the least significant bit
    if bit == '0':
        # If the bit to be embedded is 0, clear the least significant bit
        return channel & 0xFE
    else:
        # If the bit to be embedded is 1, set the least significant bit
        return channel | 0x01
    
def encrypt_stego(cover_image, message):
    height, width, depth = cover_image.shape
    binary_message = string_to_bin(message)
    message_index = 0

    for row in range(height):
        for column in range(width):
            for channel in range(depth):
                if message_index < len(binary_message):
                    channel_value = cover_image[row, column, channel]
                    bit_to_embed = binary_message[message_index]
                    modified_channel = embed_bit(channel_value, bit_to_embed)
                    cover_image[row, column, channel] = modified_channel
                    message_index += 1
                else:
                    # If the entire message has been embedded, embed end-of-message marker
                    cover_image[row, column, channel] = embed_bit(channel_value, '0')
                    return cover_image  # End embedding process
    return cover_image

def decrypt_stego(stego_image):
    binary_message = ""
    height, width, depth = stego_image.shape
    message_index = 0

    for row in range(height):
        for column in range(width):
            for channel in range(depth):
                channel_value = stego_image[row, column, channel]
                extracted_LSB = channel_value & 0x01  # Extract LSB
                binary_message += str(extracted_LSB)
                message_index += 1

                # Check for end-of-message marker (8 consecutive 0s)
                if message_index % 8 == 0 and binary_message[-8:] == '00000000':
                    return binary_message[:-8]  # Return message excluding ending marker

    # If end-of-message marker not found, return entire message
    return binary_message


#caesar cipher encryption
def encrypt_caesar(plaintext, key):
    ciphertext = ""
    for char in plaintext:
        if char.islower():
            encrypted_char = chr((ord(char) + key - ord('a')) % 26 + ord('a'))
        elif char.isupper():
            encrypted_char = chr((ord(char) + key - ord('A')) % 26 + ord('A'))
        else:
            encrypted_char = char  # Keep non-alphabetic characters unchanged
        ciphertext += encrypted_char
    return ciphertext

def binary_to_string(binary_ciphertext):
    ciphertext = ""
    for i in range(0, len(binary_ciphertext), 8):
        byte = binary_ciphertext[i:i + 8]
        char = chr(int(byte, 2))
        ciphertext += char
    return ciphertext

#caesar cipher decryption
def decrypt_caesar(ciphertext, key):
    plaintext = ""
    for char in ciphertext:
        if char.islower():
            decrypted_char = chr((ord(char) - key - ord('a')) % 26 + ord('a'))
        elif char.isupper():
            decrypted_char = chr((ord(char) - key - ord('A')) % 26 + ord('A'))
        else:
            decrypted_char = char  # Keep non-alphabetic characters unchanged
        plaintext += decrypted_char
    return plaintext


#Main code
image = cv2.imread('images.jpeg')
plaintext = input('Enter your text to be encrypted: ')
key=6
print("plaintext: ", plaintext)

#ciphertext string
ciphertext=encrypt_caesar(plaintext,key)
print("ciphertext: ", ciphertext)

#create image embedded with binary ciphertext
stego_image= encrypt_stego(image,ciphertext)
stego_img_path= "Stego_image.png"
cv2.imwrite(stego_img_path,stego_image)

#extract binary ciphertext from image
binary_ciphertext = decrypt_stego(stego_image)

# Convert binary message to string and print the original message
string_ciphertext = binary_to_string(binary_ciphertext)
print("string ciphertext: ", string_ciphertext)

string_final_text=decrypt_caesar(string_ciphertext, key)
print("Original message:", string_final_text)