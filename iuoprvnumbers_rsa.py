"""
https://upon2020.com/blog/2019/02/simple-notes-on-rsa-encryption-with-pythons-cryptography-module/
we need to stay within this guidelines 
p and q must be (large) primes. They need to be secret.
e should be choosen so that a certain function that indirectly depends on p and q evaluates to 1
n == p * q (hard to factor since p and q must be secret) --> length of the key
d is to be calculated and kept secret

n and e both public and together are public key

simple example
"""

from  base64 import b64encode,b64decode
from cryptography.hazmat.primitives.asymmetric.rsa import(
	RSAPublicNumbers,RSAPrivateNumbers,generate_private_key,RSAPrivateKey)


class RsaNumbers:

	def __init__(self):
		self._key = None

	@property
	def private_numbers_props(self):
		return {'p':self._private_key_props().p,
		'q':self._private_key_props().q,
		'd':self._private_key_props().d,
		'dmp1':self._private_key_props().dmp1,
		'dmq1':self._private_key_props().dmq1,
		'iqmp':self._private_key_props().iqmp
		} if self.isPrivateKey() else {'p':None,'q':None,'d':None,'dmp1':None,'dmq1':None,'iqmp':None}

	@property
	def public_numbers_props(self):
		return {'e':self._public_number_props().e,'n':self._public_number_props().n} 


	@property
	def private_key(self):
		return self._key if self.isPrivateKey() else None

	@property
	def public_key(self):
		return self._key.public_key if self.isPrivateKey() else self._key

	def isPrivateKey(self):
		return isinstance(self._key,RSAPrivateKey)


	def _private_key_props(self):
		self.private_key.private_numbers() if self.private_key else None 

	def _public_number_props(self):
		self.public_key.public_numbers()

def generate():
	rsa_numbers = RsaNumbers()
	rsa_numbers._key = generate_private_key(public_exponent=65537,key_size=2048,)
	rsa_numbers._private_key_props = rsa_numbers._key.private_numbers
	rsa_numbers._public_number_props = rsa_numbers._key.public_key().public_numbers
	return rsa_numbers

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


if __name__ == "__main__":
	rsa_key= generate()
	k_vals = rsa_key.private_numbers_props
	public_numbers= RSAPublicNumbers(rsa_key.public_numbers_props['e'],rsa_key.public_numbers_props['n'])
	priv_numbers = RSAPrivateNumbers(k_vals['p'],k_vals['q'],k_vals['d'],
		k_vals['dmp1'],k_vals['dmq1'],k_vals['iqmp'],public_numbers)

	data_to_encrypt = 'we are here now'
	encrypted_message = public_numbers.public_key().encrypt(data_to_encrypt.encode(),padding.PKCS1v15())
	print(encrypted_message)

	decrypted_message= priv_numbers.private_key().decrypt(encrypted_message,padding.PKCS1v15()).decode()
	print(decrypted_message)



