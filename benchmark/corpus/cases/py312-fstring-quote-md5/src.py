import hashlib

b = b"x"
s = f"{'"'}"; h = hashlib.md5(b).hexdigest(); t = 'x'  # noqa: E702
