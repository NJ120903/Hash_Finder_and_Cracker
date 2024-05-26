import re

def identify_hash(hash_value):
    hash_length = len(hash_value)
    
    # Check for common hash patterns
    if re.match(r'^[0-9a-f]{32}$', hash_value):
        return "MD5"
    elif re.match(r'^[0-9a-f]{40}$', hash_value):
        return "SHA-1 or MySQL 4.1+ (SHA-1(SHA-1_bin))"
    elif re.match(r'^[0-9a-f]{56}$', hash_value):
        return "SHA-224"
    elif re.match(r'^[0-9a-f]{64}$', hash_value):
        return "SHA-256 or Whirlpool"
    elif re.match(r'^[0-9a-f]{96}$', hash_value):
        return "SHA-384"
    elif re.match(r'^[0-9a-f]{128}$', hash_value):
        return "SHA-512"
    elif re.match(r'^\*[0-9a-f]{40}$', hash_value):
        return "MySQL 4.1+ (SHA-1(SHA-1_bin))"
    elif re.match(r'^[a-f0-9]{32}$', hash_value):
        return "NTLM"
    elif re.match(r'^[a-f0-9]{48}$', hash_value):
        return "LM"
    else:
        return "Unknown hash type"

if __name__ == "__main__":
    hash_value = input("Enter the hash value: ")
    hash_type = identify_hash(hash_value)
    print(f"The hash type is likely: {hash_type}")
