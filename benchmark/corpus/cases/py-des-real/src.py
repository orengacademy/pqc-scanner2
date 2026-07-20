from Crypto.Cipher import DES

cipher = DES.new(b"8bytekey", DES.MODE_ECB)
