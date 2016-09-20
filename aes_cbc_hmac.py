import hashlib
from hashlib import sha1
import random
import sys
from Crypto.Cipher import AES
from Crypto.Util.strxor import strxor

mode = sys.argv[2]
key = sys.argv[4]
input = sys.argv[6]
output = sys.argv[8]
mac_key = key[16:]
enc_key = key[0:16]

opad = "".join(chr(x ^ 0x5c) for x in xrange(256))
ipad = "".join(chr(x ^ 0x36) for x in xrange(256))
blocksize = 64

def convert_aes_key(key):
    converted_key = hashlib.sha256(key).digest()
    return converted_key

def message_padding(message):
    padding_length = 16 - len(message)%16
    message = message + str(padding_length) * padding_length
    return message

def read_file(file):
    f = open(file, 'r')
    plaintext = f.read()
    #    print len(plaintext)
    f.close()
    return plaintext

def write_output_file(file_name, result):
    f = open(file_name, 'w')
    f.write(result)
    f.close()

def hmac_sha1(key, message):
    if len(key)>blocksize:
        key = sha1(key).digest()
    else:
        key = key + chr(0)*(blocksize-len(key))

    o_key_pad = key.translate(opad)  # ''.join(chr(ord(k) ^ 0x5C) for k in key) same results
    i_key_pad = key.translate(ipad)  # ''.join(chr(ord(k) ^ 0x36) for k in key)
    return sha1(o_key_pad + sha1(i_key_pad+message).digest()).digest()

def stripM__(M__):
    n = str(M__[-1])
#    print M__
#    print n
    for i in range(len(n)):
        if str(M__[-1-i])!=n:
            print "Invalid Padding"
            quit()
    return M__[:-1-int(n)]

def AES_ENC(message, key):
    cipher_text = AES.new(key, AES.MODE_ECB,).encrypt(message)
    return cipher_text

def AES_DEC(key, cipher_text):
    plain_text = AES.new(key, AES.MODE_ECB,).decrypt(cipher_text)
    return plain_text

def CBC_cipher(message, key, iv):
    block_size = AES.block_size
    block_set = []
    cipher_set = []

    n = len(message) %16
    if n !=0:
        block_mun=int(len(message))+1
        for i  in range(n, 16):
            message += chr(0)
    else:
        block_mun = int(len(message)/16)
    cipher = ''
    for i in range(0, block_mun):
        block_set.append(message[i*16:(i+1)*16])
        cipher_set.append(AES_ENC(strxor(iv,block_set[i]),key))
        iv = cipher_set[i]
        cipher+= cipher_set[i]
    return cipher

def CBC_decipher(cipher, key, iv):
    block_size = AES.block_size
    block_set = []
    cipher_set = []
    block_num = len(cipher)/16
    plain_text = ''

    for i in range(0,block_num):
        cipher_set.append(cipher[i*16:(i+1)*16])
        block_set.append(strxor(AES_DEC(key,cipher_set[i]),iv))
        plain_text += block_set[i]
        iv = cipher_set[i]
    return plain_text

if __name__ == "__main__":
    if len(key) !=32:
        print "wrong size of key!"
        print "Usage : python assignment1.py -m <mode> -k <32byte key>(example: 1234567890ABCDEF1234567890ABCDEF) -i <inputfile>(example input.txt) -o <outputfile>"

    if mode == 'encrypt':
        #enc_key = convert_aes_key(enc_key)
        inputtext = read_file(input)
        Tag = hmac_sha1(mac_key,inputtext)
        M_ =inputtext + Tag
        M__ = message_padding(M_)
        iv = ''.join(chr(random.randint(0, 0xFF)) for i in range(16))
#        obj = AES.new(enc_key, AES.MODE_CBC, iv)
#        C_ = obj.encrypt(M__)
        C_ = CBC_cipher(M__,enc_key,iv)
        result = iv + C_
        write_output_file(output, result)

    if mode == 'decrypt':
        ciphertext = read_file(input)
        iv = ciphertext[:16]
#        print len(iv)
        C_ = ciphertext[16:]
#        print len(C_)
#        obj = AES.new(enc_key, AES.MODE_CBC, iv)
#        M__ = obj.decrypt(C_)
        M__ = CBC_decipher(C_,enc_key,iv)
        M_ =  stripM__(M__)
        M= M_[:-19]
        Tag= M[-20:]

        Tag=hmac_sha1(mac_key, M)
        if Tag != Tag:
            print "Invalid MAC"
            quit()
        write_output_file(output,M)
