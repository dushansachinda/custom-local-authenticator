import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class PinHashingUtil {

    // Configurable parameters for PBKDF2
    private static final String ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final int SALT_LENGTH = 16; // 16 bytes (128 bits)
    private static final int HASH_LENGTH = 256; // 256 bits
    private static final int ITERATIONS = 10000;

    /**
     * Generates a random salt.
     *
     * @return A random salt as a byte array.
     */
    public static byte[] generateSalt() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[SALT_LENGTH];
        random.nextBytes(salt);
        return salt;
    }

    /**
     * Hashes the provided PIN using PBKDF2.
     *
     * @param pin  The PIN to hash.
     * @param salt The salt to use for hashing.
     * @return A Base64-encoded string combining the salt and hashed PIN.
     * @throws NoSuchAlgorithmException If the hashing algorithm is not available.
     * @throws InvalidKeySpecException  If the key specification is invalid.
     */
    public static String hashPin(String pin, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        PBEKeySpec spec = new PBEKeySpec(pin.toCharArray(), salt, ITERATIONS, HASH_LENGTH);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(ALGORITHM);
        byte[] hash = keyFactory.generateSecret(spec).getEncoded();

        // Combine salt and hash for storage
        return Base64.getEncoder().encodeToString(salt) + ":" + Base64.getEncoder().encodeToString(hash);
    }

    /**
     * Validates the provided PIN against the stored hash.
     *
     * @param pin       The PIN to validate.
     * @param storedPin The stored hash (salt:hash format).
     * @return True if the PIN matches, false otherwise.
     * @throws NoSuchAlgorithmException If the hashing algorithm is not available.
     * @throws InvalidKeySpecException  If the key specification is invalid.
     */
    public static boolean validatePin(String pin, String storedPin)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        String[] parts = storedPin.split(":");
        byte[] salt = Base64.getDecoder().decode(parts[0]);
        byte[] storedHash = Base64.getDecoder().decode(parts[1]);

        // Hash the provided PIN with the stored salt
        PBEKeySpec spec = new PBEKeySpec(pin.toCharArray(), salt, ITERATIONS, HASH_LENGTH);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(ALGORITHM);
        byte[] hash = keyFactory.generateSecret(spec).getEncoded();

        // Compare the computed hash with the stored hash
        return java.util.Arrays.equals(hash, storedHash);
    }

    public static void main(String[] args) {
        try {
            String pin = "1234"; // Example PIN
            byte[] salt = generateSalt();

            // Hash the PIN
            String hashedPin = "FuzrmIL3BC0vbmgi3pSdvw==:17sOThML3LmTo1yuelFtZ96OeOT2jW6MAEhz9p7q8HE="; //hashPin(pin, salt);
            //System.out.println("Hashed PIN: " + hashedPin);

            // Validate the PIN
            boolean isValid = validatePin(pin, hashedPin);
            System.out.println("Is PIN valid? " + isValid);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
