# OTPad: One-time Pad

## Install

```
$ pip install otpad
```

## Usage

```
from cryptography.fernet import Fernet
import otpad

k1 = Fernet.generate_key()
k2 = Fernet.generate_key()
k3 = Fernet.generate_key()

padded = otpad.pad(k1, k2, hmac_key=k3)
orig = unpad(k1, padded['encrypted'], hmac_key=k3, hmac_digest=padded['digest'])
```