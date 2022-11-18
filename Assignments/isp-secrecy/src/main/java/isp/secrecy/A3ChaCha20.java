package isp.secrecy;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.ChaCha20ParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.Key;
import java.security.SecureRandom;

/**
 * TASK:
 * Assuming Alice and Bob know a shared secret key in advance, secure the channel using
 * ChaCha20 stream cipher. Then exchange ten messages between Alice and Bob.
 * <p>
 * https://docs.oracle.com/en/java/javase/11/docs/api/java.base/javax/crypto/Cipher.html
 */
public class A3ChaCha20 {
    public static void main(String[] args) throws Exception {
        // STEP 1: Alice and Bob beforehand agree upon a cipher algorithm and a shared secret key
        // This key may be accessed as a global variable by both agents
        final Key key = KeyGenerator.getInstance("ChaCha20").generateKey();
        final int numberOfMessages = 10;

        // STEP 2: Setup communication
        final Environment env = new Environment();

        System.out.println("Starting agent communication using ChaCha20 stream cipher..");

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                // STEP 3: Alice creates, encrypts and sends a message to Bob. Bob replies to the message.
                // Such exchange repeats 10 times.

                for (int counter = 0; counter < numberOfMessages; counter++) {
                    // Send
                    final String message = "I love you Bob. Kisses, Alice.";
                    final byte[] pt = message.getBytes();

                    final Cipher encrypt = Cipher.getInstance("ChaCha20");
                    // create empty nonce and fill it with random
                    final byte[] nonce = new byte[12];
                    new SecureRandom().nextBytes(nonce);

                    encrypt.init(Cipher.ENCRYPT_MODE, key, new ChaCha20ParameterSpec(nonce, counter));
                    final byte[] cipherText = encrypt.doFinal(pt);

                    send("bob", cipherText);
                    send("bob", nonce);
                    send("bob", new byte[] {(byte) counter});

                    // Receive
                    final byte[] cipherReply = receive("bob");
                    final byte[] nonceReply = receive("bob");
                    final byte[] counterReply = receive("bob");

                    final Cipher decrypt = Cipher.getInstance("ChaCha20");
                    decrypt.init(Cipher.DECRYPT_MODE, key, new ChaCha20ParameterSpec(nonceReply, counterReply[0]));
                    final byte[] dt = decrypt.doFinal(cipherReply);

                    print("Received no. %d: '%s'", counter+1, new String(dt));
                }
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                // STEP 4: Bob receives, decrypts and displays a message, then replies.
                // Such exchange repeats 10 times.

                for (int counter = 0; counter < numberOfMessages; counter++) {
                    // Receive
                    final byte[] cipherTextReceive = receive("alice");
                    final byte[] nonceReceive = receive("alice");
                    final byte[] counterReceive = receive("alice");

                    final Cipher decrypt = Cipher.getInstance("ChaCha20");
                    decrypt.init(Cipher.DECRYPT_MODE, key, new ChaCha20ParameterSpec(nonceReceive, counterReceive[0]));
                    final byte[] dt = decrypt.doFinal(cipherTextReceive);

                    print("Received no. %d: '%s'", counter+1, new String(dt));

                    // Reply
                    final String message = "Love you too, Alice. Bob <3";
                    final byte[] pt = message.getBytes();

                    final Cipher encrypt = Cipher.getInstance("ChaCha20");
                    // create empty nonce and fill it with random
                    final byte[] nonce = new byte[12];
                    new SecureRandom().nextBytes(nonce);

                    encrypt.init(Cipher.ENCRYPT_MODE, key, new ChaCha20ParameterSpec(nonce, counter));
                    final byte[] cipherReply = encrypt.doFinal(pt);

                    send("alice", cipherReply);
                    send("alice", nonce);
                    send("alice", new byte[] {(byte) counter});
                }
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}
