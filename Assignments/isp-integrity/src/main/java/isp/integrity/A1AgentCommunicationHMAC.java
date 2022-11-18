package isp.integrity;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * TASK:
 * Assuming Alice and Bob know a shared secret key, provide integrity to the channel
 * using HMAC implemented with SHA256. Then exchange ten messages between Alice and Bob.
 * <p>
 * https://docs.oracle.com/en/java/javase/11/docs/api/java.base/javax/crypto/Cipher.html
 */
public class A1AgentCommunicationHMAC {
    public static void main(String[] args) throws Exception {
        /*
         * Alice and Bob share a secret session key that will be
         * used for hash based message authentication code.
         */
        final Key key = KeyGenerator.getInstance("HmacSHA256").generateKey();
        final int numberOfExchanges = 5;

        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                for (int i = 0; i < numberOfExchanges; i++) {
                    final String text = "I hope you get this message intact. Kisses, Alice.";
                    final byte[] pt = text.getBytes(StandardCharsets.UTF_8);

                    // Instantiate HMAC algorithm
                    final Mac alice = Mac.getInstance("HmacSHA256");

                    // Initialize HMAC and provide shared secret session key. Create an HMAC tag.
                    alice.init(key);
                    final byte[] tag = alice.doFinal(pt);

                    // Send the message and tag to confirm integrity
                    send("bob", pt);
                    send("bob", tag);
                    print("Sent message no. %d: '%s' with tag '%s'", i+1, text, Agent.hex(tag));

                    // Receive response from bob
                    final byte[] replyPT = receive("bob");
                    final byte[] replyTag = receive("bob");

                    final byte[] tag2 = alice.doFinal(replyPT);
                    boolean integrity = verifyTags(replyTag, tag2, key);
                    print("Received reply no. %d with tag. Was reply integrity kept? %b", i+1, integrity);
                    System.out.println("---------------");
                }
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                for (int i = 0; i < numberOfExchanges; i++) {
                    // Receive message from alice
                    final byte[] pt = receive("alice");
                    final byte[] tag1 = receive("alice");

                    // Create own HMAC instance and create new tag to then verify that it has not been tampered with
                    final Mac bob = Mac.getInstance("HmacSHA256");
                    bob.init(key);
                    final byte[] tag2 = bob.doFinal(pt);
                    boolean integrity = verifyTags(tag1, tag2, key);
                    print("Received message no. %d with tag. Was message integrity kept? %b", i+1, integrity);

                    // Send response to alice
                    String reply = integrity
                            ? "I verified that the message was not tampered with. Lot's of love, Bob <3"
                            : "Somebody is trying to tamper with our messages! Let's meet at our usual spot >:(";
                    byte[] replyPT = reply.getBytes(StandardCharsets.UTF_8);
                    final byte[] replyTag = bob.doFinal(replyPT);
                    print("Sent reply no. %d: '%s' with tag '%s'", i+1, reply, Agent.hex(replyTag));
                    send("alice", replyPT);
                    send("alice", replyTag);
                }
            }
        });

        env.connect("alice", "bob");
        env.start();
    }

    public static boolean verifyTags(byte[] tag1, byte[] tag2, Key key)
            throws NoSuchAlgorithmException, InvalidKeyException {
        final Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(key);

        final byte[] tagtag1 = mac.doFinal(tag1);
        final byte[] tagtag2 = mac.doFinal(tag2);

        return Arrays.equals(tagtag1, tagtag2);
    }
}
