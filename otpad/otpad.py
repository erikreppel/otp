from operator import xor
import hmac
import hashlib
import base64


def pad(key, key_to_encrypt, hmac_key=None):
    '''
    Performs a one time pad on two strings.
    :params - key: key and key_to_encrypt are strings of equal length
            - key_to_encrypt: key and key_to_encrypt are strings of equal len
            - hmac_key: if a key is present, will add key 'digest' to return dictionary
    :returns - dictionary with key 'encrypted' which is the resultant from the XOR as a string.
               If :param hmac_key is present, will also have key 'digest' in return dictionary
    '''
    assert len(key) == len(key_to_encrypt)
    key1_bytes, key2_bytes = bytearray(key), bytearray(key_to_encrypt)
    padded = bytearray([1] * len(key1_bytes))

    for i, _ in enumerate(key1_bytes):
        padded[i] = xor(key1_bytes[i], key2_bytes[i])
    b64_padded = base64.b64encode(padded)

    if not hmac_key:
        return {'encrypted': b64_padded}

    digest = hmac.new(hmac_key, msg=b64_padded, digestmod=hashlib.sha256).digest()
    digest = base64.b64encode(digest)
    return {'encrypted': b64_padded, 'digest': digest}


def unpad(key, encrypted_key, hmac_key=None, hmac_digest=None):
    '''
    Performs a one time pad on two strings and optionally verifies the hmac.
    :params - key: key and encrypted_key are strings of equal length
            - encrypted_key: key and encrypted_key are strings of equal length
            - hmac_key: if a key is present, will verify and throw exception if not valid
    :returns - dictionary with key 'decrypted' which is the resultant from the XOR as a string.
    '''
    raw_encrypted_key = base64.b64decode(encrypted_key)
    assert len(key) == len(raw_encrypted_key)

    if hmac_key:
        if not hmac_digest:
            raise Exception('hmac_key with no hmac_digest')
        digest = hmac.new(hmac_key, msg=encrypted_key, digestmod=hashlib.sha256).digest()
        digest = base64.b64encode(digest)
        if _safe_string_compare(digest, hmac_digest) is False:
            raise Exception('computed hmac of encrypted_key does not match the hmac_digest')

    key1_bytes, key2_bytes = bytearray(key), bytearray(raw_encrypted_key)
    padded = bytearray([1] * len(key1_bytes))

    for i, _ in enumerate(key1_bytes):
        padded[i] = xor(key1_bytes[i], key2_bytes[i])
    padded = str(padded.decode('utf-8'))
    return {'decrypted': padded}


def _safe_string_compare(string1, string2):
    same = True
    max_length = max(len(string1), len(string2))
    for i in range(max_length):
        if len(string1) <= i or len(string2) <= i:
            continue
        if string1[i] != string2[i]:
            same = False
    return same
