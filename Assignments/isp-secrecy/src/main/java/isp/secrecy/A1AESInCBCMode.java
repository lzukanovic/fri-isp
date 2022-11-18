package isp.secrecy;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import java.security.Key;

/**
 * TASK:
 * Assuming Alice and Bob know a shared secret key in advance, secure the channel using
 * AES in CBC mode. Then exchange ten messages between Alice and Bob.
 * <p>
 * https://docs.oracle.com/en/java/javase/11/docs/api/java.base/javax/crypto/Cipher.html
 */
public class A1AESInCBCMode {
    public static void main(String[] args) throws Exception {
        // STEP 1: Alice and Bob beforehand agree upon a cipher algorithm and a shared secret key
        // This key may be accessed as a global variable by both agents
        final Key key = KeyGenerator.getInstance("AES").generateKey();
        final int numberOfMessages = 10;

        // STEP 2: Setup communication
        final Environment env = new Environment();

        System.out.println("Starting agent communication using AES in CBC mode..");

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                // STEP 3: Alice creates, encrypts and sends a message to Bob. Bob replies to the message.
                // Such exchange repeats 10 times.

                for (int i = 0; i < numberOfMessages; i++) {
                    // Send
                    final String message = "I love you Bob. Kisses, Alice.";
                    final byte[] pt = message.getBytes();

                    final Cipher encrypt = Cipher.getInstance("AES/CBC/PKCS5Padding");
                    encrypt.init(Cipher.ENCRYPT_MODE, key);
                    final byte[] cipherText = encrypt.doFinal(pt);
                    final byte[] iv = encrypt.getIV();

                    send("bob", cipherText);
                    send("bob", iv);

                    // Receive
                    final byte[] cipherReply = receive("bob");
                    final byte[] ivReply = receive("bob");
                    final Cipher decrypt = Cipher.getInstance("AES/CBC/PKCS5Padding");
                    decrypt.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(ivReply));
                    final byte[] dt = decrypt.doFinal(cipherReply);

                    print("Received no. %d: '%s'", i+1, new String(dt));
                }
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                // STEP 4: Bob receives, decrypts and displays a message, then replies.
                // Such exchange repeats 10 times.

                for (int i = 0; i < numberOfMessages; i++) {
                    // Receive
                    final byte[] cipherText = receive("alice");
                    final byte[] iv = receive("alice");
                    final Cipher decrypt = Cipher.getInstance("AES/CBC/PKCS5Padding");
                    decrypt.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
                    final byte[] dt = decrypt.doFinal(cipherText);

                    print("Received no. %d: '%s'", i+1, new String(dt));

                    // Reply
                    final String message = "Love you too, Alice. Bob <3";
                    final byte[] pt = message.getBytes();

                    final Cipher encrypt = Cipher.getInstance("AES/CBC/PKCS5Padding");
                    encrypt.init(Cipher.ENCRYPT_MODE, key);
                    final byte[] cipherReply = encrypt.doFinal(pt);
                    final byte[] ivReply = encrypt.getIV();

                    send("alice", cipherReply);
                    send("alice", ivReply);
                }
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}
