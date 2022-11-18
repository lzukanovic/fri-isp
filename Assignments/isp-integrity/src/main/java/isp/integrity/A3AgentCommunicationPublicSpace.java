package isp.integrity;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.*;

/**
 * TASK:
 * We want to send a large chunk of data from Alice to Bob while maintaining its integrity and considering
 * the limitations of communication channels -- we have three such channels:
 * - Alice to Bob: an insecure channel, but has high bandwidth and can thus transfer large files
 * - Alice to Public Space: a secure channel, but has low bandwidth and can only transfer small amounts of data
 * - Bob to Public Space: a secure channel, but has low bandwidth and can only transfer small amounts of data
 * <p>
 * The plan is to make use of the public-space technique:
 * - Alice creates the data and computes its digest
 * - Alice sends the data to Bob, and sends the encrypted digest to Public Space
 * - Channel between Alice and Public space is secured with ChaCha20-Poly1305 (Alice and Public space share
 * a ChaCha20 key)
 * - Public space forwards the digest to Bob
 * - The channel between Public Space and Bob is secured but with AES in GCM mode (Bob and Public space share
 * an AES key)
 * - Bob receives the data from Alice and the digest from Public space
 * - Bob computes the digest over the received data and compares it to the received digest
 * <p>
 * Further instructions are given below.
 * <p>
 * https://docs.oracle.com/en/java/javase/11/docs/api/java.base/javax/crypto/Cipher.html
 */
public class A3AgentCommunicationPublicSpace {
    public static void main(String[] args) throws Exception {
        final Environment env = new Environment();

        // Create a ChaCha20 key that is used by Alice and the public-space
        final Key cha20Key = KeyGenerator.getInstance("ChaCha20").generateKey();
        // Create an AES key that is used by Bob and the public-space
        final Key aesKey = KeyGenerator.getInstance("AES").generateKey();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                // a payload of 200 MB
                final byte[] data = new byte[200 * 1024 * 1024];
                new SecureRandom().nextBytes(data);

                // Alice sends the data directly to Bob
                // The channel between Alice and Bob is not secured
                send("bob", data);

                // Alice then computes the digest of the data and sends the digest to public-space
                final MessageDigest digestAlgorithm = MessageDigest.getInstance("SHA-256");
                final byte[] digest = digestAlgorithm.digest(data);

                // The channel between Alice and the public-space is secured with ChaCha20-Poly1305
                // Use the key that you have created above.
                final Cipher alice = Cipher.getInstance("ChaCha20-Poly1305");
                alice.init(Cipher.ENCRYPT_MODE, cha20Key);
                final byte[] ct = alice.doFinal(digest);
                final byte[] iv = alice.getIV();
                send("public-space", ct);
                send("public-space", iv);
            }
        });

        env.add(new Agent("public-space") {
            @Override
            public void task() throws Exception {
                // Receive the encrypted digest from Alice and decrypt ChaCha20 and
                // the key that you share with Alice
                final byte[] aliceCt = receive("alice");
                final byte[] aliceIv = receive("alice");

                final Cipher psCha20Cipher = Cipher.getInstance("ChaCha20-Poly1305");
                psCha20Cipher.init(Cipher.DECRYPT_MODE, cha20Key, new IvParameterSpec(aliceIv));
                final byte[] alicePt = psCha20Cipher.doFinal(aliceCt);

                // Encrypt the digest with AES-GCM and the key that you share with Bob and
                // send the encrypted digest to Bob
                final Cipher psAesGcmCipher = Cipher.getInstance("AES/GCM/NoPadding");
                psAesGcmCipher.init(Cipher.ENCRYPT_MODE, aesKey);
                final byte[] bobCt = psAesGcmCipher.doFinal(alicePt);
                final byte[] bobIv = psAesGcmCipher.getIV();
                send("bob", bobCt);
                send("bob", bobIv);
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                // Receive the data from Alice and compute the digest over it using SHA-256
                final byte[] aliceData = receive("alice");
                final MessageDigest digestAlgorithm = MessageDigest.getInstance("SHA-256");
                final byte[] aliceDigest = digestAlgorithm.digest(aliceData);

                // Receive the encrypted digest from the public-space, decrypt it using AES-GCM
                // and the key that Bob shares with the public-space
                final byte[] psCt = receive("public-space");
                final byte[] psIv = receive("public-space");
                final Cipher bobAesGcmCipher = Cipher.getInstance("AES/GCM/NoPadding");
                bobAesGcmCipher.init(Cipher.DECRYPT_MODE, aesKey, new GCMParameterSpec(128, psIv));
                final byte[] psDigest = bobAesGcmCipher.doFinal(psCt);

                // Compare the computed digest and the received digest and print the string
                // "data valid" if the verification succeeds, otherwise print "data invalid"
                boolean validity = verifyDigests(aliceDigest, psDigest);
                print(validity ? "data valid" : "data invalid");
            }
        });

        env.connect("alice", "bob");
        env.connect("alice", "public-space");
        env.connect("public-space", "bob");
        env.start();
    }

    public static boolean verifyDigests(byte[] tag1, byte[] tag2) {
        if (tag1 == tag2)
            return true;
        if (tag1 == null || tag2 == null)
            return false;

        int length = tag1.length;
        if (tag2.length != length)
            return false;

        // This loop never terminates prematurely
        byte result = 0;
        for (int i = 0; i < length; i++) {
            result |= tag1[i] ^ tag2[i];
        }
        return result == 0;
    }
}
