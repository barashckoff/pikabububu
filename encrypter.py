from Crypto.PublicKey import RSA
import random
import hashlib

print('Do you already have a keypair?\n\n')
print('Y/N')
answer = input()
if answer == 'Y':
    print('Good! Can you tell your secret key to find your keypair?')
    code = input('Write it right here \n>')
    code = hashlib.sha1(code.encode('utf8')).hexdigest()
    pubkey = str(code + ".pukey")
    prkey = str(code + ".prkey")
    ext = str(code + ".bin")
    
else:
    print('OK. We will create new keypair for you. \n\n\n Please wait...')
    code = str(random.getrandbits(1024))
    print('Your new secret code is \n\n\n -----------------------\n'+ code)
    print('Please choose the desired key size. Remember that it must be longer than 1024 bits')
    klng = int(input('Write it right here\n>'))
    print('\n\n <HELPER> GENERATING NEW KEYPAIR')
    key = RSA.generate(klng)
    code = hashlib.sha1(code.encode('utf8')).hexdigest()
    pubkey = str(code + ".pukey")
    prkey = str(code + ".prkey")
    ext = str(code + ".bin")
    scode = str(code + ".scode")
    print('\n' + code + '\n')
    encrypted_key = key.exportKey(
        passphrase=code, 
        pkcs=8, 
        protection="scryptAndAES128-CBC"
    )

    with open(prkey, 'wb') as f:
        f.write(encrypted_key)
     
    with open(pubkey, 'wb') as f:
        f.write(key.publickey().exportKey())
print('<HELPER> DONE')
print('Can you tell me your file name?')
oname =  input()
"""FILE ENCODE"""
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
with open(ext, 'wb') as out_file:
    recipient_key = RSA.import_key(
        open(pubkey).read()
    )
    
    session_key = get_random_bytes(16)
    
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    out_file.write(cipher_rsa.encrypt(session_key))
    
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    f = open(oname, 'r')
    data = f.read().encode('utf8')
    ciphertext, tag = cipher_aes.encrypt_and_digest(data)
    
    out_file.write(cipher_aes.nonce)
    out_file.write(tag)
    out_file.write(ciphertext)
