package isp.secrecy;

import fri.isp.Agent;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import java.security.Key;

/**
 * EXERCISE:
 * - Study the example
 * - Test different ciphers
 *
 * https://docs.oracle.com/en/java/javase/11/docs/api/java.base/javax/crypto/Cipher.html
 */
public class SymmetricCipherExample {
    public static void main(String[] args) throws Exception {
        final String message = "Hi Bob, this is Alice.";
        System.out.println("[MESSAGE] " + message);

        // A lot of code duplication, but better for understanding
        // Uncomment specific encryption algorithm and change in/correct key usage
        // ------
        runInRc4(message, true);
        //runInAesCtr(message, true);
    }

    /**
     * When using the incorrect key the output is gibberish, otherwise the message is successfully decrypted
     */
    private static void runInRc4(String message, boolean useCorrectKey) throws Exception {
        // STEP 1: Alice and Bob agree upon a cipher and a shared secret key
        final Key key = KeyGenerator.getInstance("RC4").generateKey();
        final Key key2 = KeyGenerator.getInstance("RC4").generateKey();

        final byte[] pt = message.getBytes();
        System.out.println("[PT] " + Agent.hex(pt));

        //  STEP 2: Create a cipher, encrypt the PT and, optionally, extract cipher parameters (such as IV)
        final Cipher encrypt = Cipher.getInstance("RC4");
        encrypt.init(Cipher.ENCRYPT_MODE, key);
        final byte[] cipherText = encrypt.doFinal(pt);

        // STEP 3: Print out cipher text (in HEX) [this is what an attacker would see]
        System.out.println("[CT] " + Agent.hex(cipherText));

        /*
         * STEP 4.
         * The receiver creates a Cipher object, defines the algorithm, the secret key and
         * possibly additional parameters (such as IV), and then decrypts the cipher text
         */
        final Cipher decrypt = Cipher.getInstance("RC4");
        decrypt.init(Cipher.DECRYPT_MODE, useCorrectKey ? key : key2);
        final byte[] dt = decrypt.doFinal(cipherText);
        System.out.println("[PT] " + Agent.hex(dt));

        // STEP 5: Create a string from a byte array
        System.out.println("[MESSAGE] " + new String(dt));
    }

    /**
     * When using the incorrect key the output is gibberish, otherwise the message is successfully decrypted
     */
    private static void runInAesCtr(String message, boolean useCorrectKey) throws Exception {
        // STEP 1: Alice and Bob agree upon a cipher and a shared secret key
        final Key key = KeyGenerator.getInstance("AES").generateKey();
        final Key key2 = KeyGenerator.getInstance("AES").generateKey();

        final byte[] pt = message.getBytes();
        System.out.println("[PT] " + Agent.hex(pt));

        //  STEP 2: Create a cipher, encrypt the PT and, optionally, extract cipher parameters (such as IV)
        final Cipher encrypt = Cipher.getInstance("AES/CTR/NoPadding");
        encrypt.init(Cipher.ENCRYPT_MODE, key);
        final byte[] cipherText = encrypt.doFinal(pt);
        final byte[] iv = encrypt.getIV();

        // STEP 3: Print out cipher text (in HEX) [this is what an attacker would see]
        System.out.println("[CT] " + Agent.hex(cipherText));

        /*
         * STEP 4.
         * The receiver creates a Cipher object, defines the algorithm, the secret key and
         * possibly additional parameters (such as IV), and then decrypts the cipher text
         */
        final Cipher decrypt = Cipher.getInstance("AES/CTR/NoPadding");
        decrypt.init(Cipher.DECRYPT_MODE, useCorrectKey ? key : key2, new IvParameterSpec(iv));
        final byte[] dt = decrypt.doFinal(cipherText);
        System.out.println("[PT] " + Agent.hex(dt));

        // STEP 5: Create a string from a byte array
        System.out.println("[MESSAGE] " + new String(dt));
    }
}
