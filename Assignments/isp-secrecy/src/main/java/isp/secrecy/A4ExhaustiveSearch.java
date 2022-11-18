package isp.secrecy;

import fri.isp.Agent;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.reflect.Array;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.Key;
import java.security.SecureRandom;
import java.text.DecimalFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Implement a brute force key search (exhaustive key search) if you know that the
 * message is:
 * "I would like to keep this text confidential Bob. Kind regards, Alice."
 * <p>
 * Assume the message was encrypted with "DES/ECB/PKCS5Padding".
 * Also assume that the key was poorly chosen. In particular, as an attacker,
 * you are certain that all bytes in the key, with the exception of th last three bytes,
 * have been set to 0.
 * <p>
 * The length of DES key is 8 bytes.
 * <p>
 * To manually specify a key, use the class {@link javax.crypto.spec.SecretKeySpec})
 */
public class A4ExhaustiveSearch {
    public static void main(String[] args) throws Exception {
        final String message = "I would like to keep this text confidential Bob. Kind regards, Alice.";
        System.out.println("[MESSAGE] " + message);

        // create key to specs
        final byte[] keySpec = prepareKeySpec();
        final SecretKey key = new SecretKeySpec(keySpec, "DES");
        System.out.println("[KEY] " + Agent.hex(keySpec));

        final byte[] pt = message.getBytes();
        System.out.println("[PT] " + Agent.hex(pt));

        // encrypt message
        final Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        final byte[] cipherText = cipher.doFinal(pt);

        System.out.println("[CT] " + Agent.hex(cipherText));

        // find key with brute force
        System.out.println("------------------------------");
        System.out.println("Starting brute force attack...");
        byte[] bruteForcedKey = bruteForceKey(cipherText, message);
        System.out.println("[BRUTE FORCED KEY] " + Agent.hex(bruteForcedKey));
    }

    public static byte[] bruteForceKey(byte[] ct, String message) throws Exception {
        long startTime = System.nanoTime();

        // create initial key with all zeros
        byte[] keySpec = new byte[8];
        // number of keys to generate is all possible permutations for 3 bytes, so 2^24
        final int steps = (int) Math.pow(2, 24);

        // create a bytebuffer to hold each key
        ByteBuffer byteBuffer = ByteBuffer.allocate(8);
        byteBuffer.order(ByteOrder.BIG_ENDIAN);

        // generate each possible key
        for (int i = 0; i < steps; i++) {
            // reset buffer
            byteBuffer.clear();
            // create key from current step/index
            // because int is 4 bytes, write first 4 with 0 and second 4 bytes with the step
            keySpec = byteBuffer.putInt(0).putInt(i).array();

            try {
                // decrypt using current key
                final Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
                final SecretKey key = new SecretKeySpec(keySpec, "DES");
                cipher.init(Cipher.DECRYPT_MODE, key);
                final byte[] plainText = cipher.doFinal(ct);

                // compare cipher text to original
                if (new String(plainText).equals(message)) {
                    System.out.printf("Successfully brute forced key! Original message was: '%s'\n", message);
                    // additional info
                    DecimalFormat formatter = new DecimalFormat("#,###");
                    long elapsedTime = System.nanoTime() - startTime;
                    String timeFormatted = elapsedTime < 1000000000 ? elapsedTime/1000000 + "ms" : elapsedTime/1000000000 + "s";
                    System.out.printf("Tried %s keys in %s before finding correct one.\n",
                            formatter.format((double) i),
                            timeFormatted);
                    break;
                }
            } catch (BadPaddingException ignored) {}
        }

        return keySpec;
    }

    /**
     * concat the two parts of the key together, first 5 byte are all zeros, last 3 bytes are random
     * together 8 byte key, ready for DES and following assignment specification
     */
    private static byte[] prepareKeySpec() throws IOException {
        final byte[] keyFirstPart = new byte[5];
        final byte[] keyLastPart = new byte[3];
        new SecureRandom().nextBytes(keyLastPart);

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
        outputStream.write(keyFirstPart);
        outputStream.write(keyLastPart);
        return outputStream.toByteArray();
    }
}
