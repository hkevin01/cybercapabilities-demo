from keygen import generate_license, derive_key, xor_bytes

def test_roundtrip():
    user = "testuser"
    lic = generate_license(user)
    # Reverse-engineered property: xor back should equal derive_key
    assert xor_bytes(lic, 0x5A) == derive_key(user)
