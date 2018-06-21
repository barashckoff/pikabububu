from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
 
import hashlib

code = str(input('Write your secret code here please: \n> '))

code = hashlib.sha1(code.encode('utf8')).hexdigest()
print('OK. Give me a second...')
pubkey = str(code + ".pukey")
prkey = str(code + ".prkey")
ext = str(code + ".bin")

with open(ext, 'rb') as fobj:
    private_key = RSA.import_key(
        open(prkey).read(),
        passphrase=code
    )
    
    enc_session_key, nonce, tag, ciphertext = [
        fobj.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1)
    ]
    
    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(enc_session_key)
    
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    data = cipher_aes.decrypt_and_verify(ciphertext, tag)
 
print('\n\n\n\n\n')
print(data)
