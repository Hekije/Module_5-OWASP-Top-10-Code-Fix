// OWASP A02:2021 - Cryptographic Failures
// Secure password hashing using PBKDF2

import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Base64;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class SecurePasswordHash {

    private static final int ITERATIONS = 210000;
    private static final int KEY_LENGTH = 256;
    private static final int SALT_LENGTH = 16;

    public static String hashPassword(String password) throws Exception {

        // Generate a cryptographically secure random salt
        SecureRandom random = new SecureRandom();

        byte[] salt = new byte[SALT_LENGTH];
        random.nextBytes(salt);

        // Create PBKDF2 password hash
        KeySpec spec = new PBEKeySpec(
                password.toCharArray(),
                salt,
                ITERATIONS,
                KEY_LENGTH);

        SecretKeyFactory factory = SecretKeyFactory.getInstance(
                "PBKDF2WithHmacSHA256");

        byte[] hash = factory.generateSecret(spec).getEncoded();

        // Store the salt and hash together
        String encodedSalt = Base64.getEncoder().encodeToString(salt);

        String encodedHash = Base64.getEncoder().encodeToString(hash);

        return encodedSalt + ":" + encodedHash;
    }

    public static void main(String[] args) {

        try {

            String password = "ExamplePassword123!";

            String hashedPassword = hashPassword(password);

            System.out.println(
                    "Original password: " + password);

            System.out.println(
                    "Stored hash: " + hashedPassword);

        } catch (Exception e) {

            System.out.println(
                    "Error hashing password.");
        }
    }
}
