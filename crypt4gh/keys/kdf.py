#######################################################################
## Key Derivation
#######################################################################
try:
    from hashlib import scrypt
    scrypt_supported = True
except:
    #import sys
    #print('Warning: No support for scrypt', file=sys.stderr)
    scrypt_supported = False


# Supported Key Derivation functions
# We'll pick scrypt when available, and bcrypt if not
# In fact, don't bother about pbkdf2_hmac_sha256
KDFS = {
    b'scrypt': (16, 0),
    b'bcrypt': (16, 100),
    b'pbkdf2_hmac_sha256': (16, 100000),
}

def get_kdf(kdfname):
    global KDFs
    info = KDFS.get(kdfname)
    if info is None:
        raise ValueError(f'Unsupported KDF: {kdfname}')
    return info

def derive_key(alg, passphrase, salt, rounds, dklen=32):
    if alg == b'scrypt':
        if not scrypt_supported:
            raise ValueError("scrypt is not supported on this plateform")
        return scrypt(passphrase, salt=salt, n=1<<14, r=8, p=1, dklen=dklen)
    if alg == b'bcrypt':
        import bcrypt
        return bcrypt.kdf(passphrase, salt=salt, desired_key_bytes=dklen, rounds=rounds,
                          # We can't control how many rounds are on disk, so no sense warning about it.
                          ignore_few_rounds=True)
    if alg == b'pbkdf2_hmac_sha256':
        from hashlib import pbkdf2_hmac
        return pbkdf2_hmac('sha256', passphrase, salt, rounds, dklen=dklen)
    raise NotImplementedError(f'Unsupported KDF: {alg}')
