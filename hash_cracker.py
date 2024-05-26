import hashlib
import sys
from passlib.hash import lmhash, nthash

def hash_cracker(hash_to_crack, password, hash_type):
    if hash_type == "lm":
        return lmhash.hash(password) == hash_to_crack
    elif hash_type == "ntlm":
        return nthash.hash(password) == hash_to_crack
    elif hash_type == "md2":
        return hashlib.new('md2', password.encode()).hexdigest() == hash_to_crack
    elif hash_type == "md4":
        return hashlib.new('md4', password.encode()).hexdigest() == hash_to_crack
    elif hash_type == "md5":
        return hashlib.md5(password.encode()).hexdigest() == hash_to_crack
    elif hash_type == "md5(md5_hex)":
        return hashlib.md5(hashlib.md5(password.encode()).hexdigest().encode()).hexdigest() == hash_to_crack
    elif hash_type == "md5-half":
        return hashlib.md5(password.encode()).hexdigest()[:16] == hash_to_crack
    elif hash_type == "sha1":
        return hashlib.sha1(password.encode()).hexdigest() == hash_to_crack
    elif hash_type == "sha224":
        return hashlib.sha224(password.encode()).hexdigest() == hash_to_crack
    elif hash_type == "sha256":
        return hashlib.sha256(password.encode()).hexdigest() == hash_to_crack
    elif hash_type == "sha384":
        return hashlib.sha384(password.encode()).hexdigest() == hash_to_crack
    elif hash_type == "sha512":
        return hashlib.sha512(password.encode()).hexdigest() == hash_to_crack
    elif hash_type == "ripemd160":
        return hashlib.new('ripemd160', password.encode()).hexdigest() == hash_to_crack
    elif hash_type == "whirlpool":
        return hashlib.new('whirlpool', password.encode()).hexdigest() == hash_to_crack
    elif hash_type == "mysql4.1":
        return hashlib.sha1(hashlib.sha1(password.encode()).digest()).hexdigest() == hash_to_crack
    elif hash_type == "qubesv3.1":
        # Add the specific algorithm for QubesV3.1BackupDefaults if known
        pass
    return False

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python hash_cracker_direct.py <hash> <password> <hash_type>")
        sys.exit(1)

    hash_to_crack = sys.argv[1]
    password = sys.argv[2]
    hash_type = sys.argv[3]

    if hash_cracker(hash_to_crack, password, hash_type):
        print(f"Password '{password}' matches the hash!")
    else:
        print(f"Password '{password}' does not match the hash.")
