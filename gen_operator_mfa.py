import pyotp
secret = pyotp.random_base32()
print(f"Operator MFA Secret: {secret}")
totp = pyotp.TOTP(secret)
print(f"Current code: {totp.now()}")