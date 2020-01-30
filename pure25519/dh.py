from pure25519.basic import random_scalar, Base, bytes_to_element
from hashlib import sha256
from typing import Callable, Tuple

# In practice, you should use the Curve25519 function, which is better in
# every way. But this is an example of what Diffie-Hellman looks like.


def dh_start(entropy_f: Callable) -> Tuple[int, bytes]:
    x = random_scalar(entropy_f)
    X = Base.scalarmult(x)
    return x, X.to_bytes()


def dh_finish(x: int, Y_s: bytes) -> bytes:
    Y = bytes_to_element(Y_s)
    XY = Y.scalarmult(x)
    return sha256(XY.to_bytes()).digest()
