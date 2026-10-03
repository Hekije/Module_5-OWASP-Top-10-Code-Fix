# OWASP A02:2021 - Cryptographic Failures
# Secure password hashing example

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)


def hash_password(password):
    """
    Securely hashes a password using scrypt.
    """
    return generate_password_hash(
        password,
        method="scrypt"
    )


def verify_password(stored_hash, password):
    """
    Checks whether a password matches
    the stored password hash.
    """
    return check_password_hash(
        stored_hash,
        password
    )


if __name__ == "__main__":

    password = "ExamplePassword123!"

    hashed_password = hash_password(password)

    print("Original password:")
    print(password)

    print("\nSecure hash:")
    print(hashed_password)

    print("\nCorrect password test:")
    print(
        verify_password(
            hashed_password,
            "ExamplePassword123!"
        )
    )

    print("\nWrong password test:")
    print(
        verify_password(
            hashed_password,
            "WrongPassword"
        )
    )