import hashlib

import hmac

from ecdsa import SigningKey, SECP256k1



def mnemonic_to_seed_electrum(mnemonic, passphrase=""):

    salt = "electrum" + passphrase

    return hashlib.pbkdf2_hmac("sha512", mnemonic.encode("utf-8"), salt.encode("utf-8"), 2048, dklen=64)



def generate_master_key(seed):

    h = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()

    return h[:32], h[32:]



def private_to_public(private_key):

    sk = SigningKey.from_string(private_key, curve=SECP256k1)

    vk = sk.verifying_key

    public_key = b'\x02' + vk.to_string()[:32] if vk.to_string()[-1] % 2 == 0 else b'\x03' + vk.to_string()[:32]

    return public_key



def get_fingerprint(public_key):

    hash160 = hashlib.new('ripemd160', hashlib.sha256(public_key).digest()).digest()

    return hash160[:4]  # First 4 bytes



with open("english.txt", "r") as file:

    wordlist = file.read().splitlines()



base_mnemonic = "civil isolate satoshi crisp issue spawn august phrase spy stool"



# Target fingerprint

target_fingerprint = bytes.fromhex("635013dd")



def print_found_message():

    print("""

  █████▒ ██████   █    ██  ███▄    █ ▓█████     ▄▄▄▄    ██████  ██▓ ██████  ██░ ██

▓██   ▒▒██    ▒   ██  ▓██▒ ██ ▀█   █ ▓█   ▀    ▓█████▄ ▒██    ▒ ▓██▒██    ▒ ▓██░ ██▒

▒████ ░░ ▓██▄     ▓██  ▒██░▓██  ▀█ ██▒▒███      ▒██▒ ▄██░ ▓██▄   ▒██░ ▓██▄   ▒██▀▀██░

░▓█▒  ░  ▒   ██▒  ▓▓█  ░██░▓██▒  ▐▌██▒▒▓█  ▄    ▒██░█▀    ▒   ██▒░██░ ▒   ██▒░▓█ ░██ 

░▒█░   ▒██████▒▒   ▒▒█████▓ ▒██░   ▓██░░▒████▒   ░▓█  ▀█▓▒██████▒▒░██▒██████▒▒░▓█▒░██▓

 ▒ ░   ▒ ▒▓▒ ▒ ░    ░▒▓▒ ▒ ▒ ░ ▒░   ▒ ▒ ░░ ▒░ ░   ▒▓███▀▒▒ ▒▓▒ ▒ ░░▓ ▒ ▒▓▒ ▒ ░ ▒ ░░▒░▒

 ░     ░ ░▒  ░ ░    ░░▒░ ░ ░ ░ ░░   ░ ▒░ ░ ░  ░   ▒░▒   ░░ ░▒  ░ ░ ▒ ░ ░▒  ░ ░ ▒ ░▒░ ░

 ░ ░   ░  ░  ░       ░░░ ░ ░    ░   ░ ░    ░       ░    ░░  ░  ░   ▒ ░  ░  ░   ░  ░░ ░

             ░         ░                 ░  ░    ░             ░   ░         ░  ░  ░

""")

for word1 in wordlist:

    for word2 in wordlist:

        mnemonic = f"{base_mnemonic} {word1} {word2}"

        seed = mnemonic_to_seed_electrum(mnemonic)

        master_private_key, _ = generate_master_key(seed)

        master_public_key = private_to_public(master_private_key)

        fingerprint = get_fingerprint(master_public_key)

        

        print(f"Testing Mnemonic: {mnemonic}")

        print(f"Generated Fingerprint: {fingerprint.hex()}")



        if fingerprint == target_fingerprint:

            with open("found.txt", "w") as f:

                f.write(f"Matching Mnemonic: {mnemonic}\n")

                f.write(f"Root Fingerprint: {fingerprint.hex()}\n")



            print_found_message()

            print(f"Matching Mnemonic: {mnemonic}")

            print(f"Root Fingerprint: {fingerprint.hex()}")

            exit(0)  
