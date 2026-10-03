// OWASP A07:2021
// Identification and Authentication Failures
// Secure password storage and verification

import org.mindrot.jbcrypt.BCrypt;

public class AuthenticationFix {

        /**
         * Hash a new password before storing it
         */
        public static String hashPassword(
                        String password) {

                return BCrypt.hashpw(
                                password,
                                BCrypt.gensalt(12));
        }

        /**
         * Verify a login password
         */
        public static boolean authenticate(
                        String inputPassword,
                        String storedPasswordHash) {

                if (inputPassword == null ||
                                storedPasswordHash == null) {
                        return false;
                }

                try {

                        return BCrypt.checkpw(
                                        inputPassword,
                                        storedPasswordHash);

                } catch (IllegalArgumentException error) {

                        return false;
                }
        }

        public static void main(String[] args) {

                String password = "ExamplePassword123!";

                String passwordHash = hashPassword(password);

                System.out.println(
                                "Password hash:");

                System.out.println(
                                passwordHash);

                boolean correctPassword = authenticate(
                                "ExamplePassword123!",
                                passwordHash);

                boolean wrongPassword = authenticate(
                                "WrongPassword",
                                passwordHash);

                System.out.println(
                                "\nCorrect password:");

                System.out.println(
                                correctPassword);

                System.out.println(
                                "\nWrong password:");

                System.out.println(
                                wrongPassword);
        }
}