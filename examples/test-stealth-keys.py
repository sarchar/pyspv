import pyspv

def main():
    bob_key = pyspv.keys.PrivateKey.create_new()
    bob_public_key = bob_key.get_public_key(True)
    print("Bob's public key =", bob_public_key.as_hex())
    
    # Alice wants to pay Bob. Bob gives Alice his public key. Alice creates a new key and multiplies Bob's public key with her private key and sends her public key to Bob.
    alice_key = pyspv.keys.PrivateKey.create_new()
    alice_public_key = alice_key.get_public_key(True)
    alice_shared_secret_point = bob_public_key.multiply(alice_key.as_int())
    print("Ephemeral key (Bob needs this to redeem) =", alice_public_key.as_hex())
    
    # Phase two is to hash the shared secret
    import hashlib
    hasher = hashlib.sha256()
    hasher.update(alice_shared_secret_point.pubkey)
    shared_secret = hasher.digest()
    
    print("Shared secret =", pyspv.bytes_to_hexstring(shared_secret, reverse=False))
    
    # We need to add shared_secret to Bob's public key
    new_bob_public_key = bob_public_key.add_constant(int.from_bytes(shared_secret, 'big'))
    print("New Bob Public Key =", new_bob_public_key.as_hex())
    print("New Bob Payment Address =", new_bob_public_key.as_address(pyspv.Bitcoin))
    
    # In order to compute the private key to new_bob_public_key, Bob has work to do.  First Bob multiplies the ephemeral key produced by alice by his private key:
    bob_shared_secret_point = alice_public_key.multiply(bob_key.as_int())
    
    # And hashes it to produce the shared secret
    hasher = hashlib.sha256()
    hasher.update(bob_shared_secret_point.pubkey)
    shared_secret_by_bob = hasher.digest()
    print("Bob figured out the shared secret =", shared_secret_by_bob == shared_secret)
    
    # Bob adds the shared secret to his private key. This works because, given Q=dG, then (d+n)G=dG+nG=Q+nG  (and alice computed Q+nG above and sent money to it, but now we know the private key d+n).
    new_bob_key = bob_key.add_constant(int.from_bytes(shared_secret_by_bob, 'big'))
    new_bob_computed_public_key = new_bob_key.get_public_key(True)
    print("Bob figured out the correct private key =", new_bob_computed_public_key.pubkey == new_bob_public_key.pubkey)

if __name__ == "__main__":
    main()

