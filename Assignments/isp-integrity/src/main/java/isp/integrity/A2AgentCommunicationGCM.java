package isp.integrity;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.Key;

/**
 * TASK:
 * Assuming Alice and Bob know a shared secret key, secure the channel using
 * AES in GCM. Then exchange ten messages between Alice and Bob.
 * <p>
 * https://docs.oracle.com/en/java/javase/11/docs/api/java.base/javax/crypto/Cipher.html
 */
public class A2AgentCommunicationGCM {
    public static void main(String[] args) throws Exception {
        /*
         * Alice and Bob share a secret session key that will be
         * used for AES in GCM.
         */
        final Key key = KeyGenerator.getInstance("AES").generateKey();
        final int numberOfExchanges = 5;

        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                for (int i = 0; i < numberOfExchanges; i++) {
                    // SEND
                    // payload
                    final String text = "I hope you get this message intact and in secret. Kisses, Alice.";
                    final byte[] pt = text.getBytes(StandardCharsets.UTF_8);

                    // encrypt and send message
                    final Cipher alice = Cipher.getInstance("AES/GCM/NoPadding");
                    alice.init(Cipher.ENCRYPT_MODE, key);
                    final byte[] ct = alice.doFinal(pt);
                    send("bob", ct);

                    // send IV
                    final byte[] iv = alice.getIV();
                    send("bob", iv);

                    // RECEIVE
                    final byte[] receiveCt = receive("bob");
                    final byte[] receiveIv = receive("bob");

                    // decrypt reply
                    final GCMParameterSpec specs = new GCMParameterSpec(128, receiveIv);
                    alice.init(Cipher.DECRYPT_MODE, key, specs);
                    final byte[] replyPt = alice.doFinal(receiveCt);

                    print("Received reply no. %d: '%s'", i+1, new String(replyPt));
                    System.out.println("---------------");
                }
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                for (int i = 0; i < numberOfExchanges; i++) {
                    // RECEIVE
                    final byte[] receiveCt = receive("alice");
                    final byte[] receiveIv = receive("alice");

                    // decrypt message
                    final Cipher bob = Cipher.getInstance("AES/GCM/NoPadding");
                    final GCMParameterSpec specs = new GCMParameterSpec(128, receiveIv);
                    bob.init(Cipher.DECRYPT_MODE, key, specs);
                    final byte[] pt = bob.doFinal(receiveCt);
                    print("Received message no. %d: '%s'", i+1, new String(pt));

                    // REPLY
                    // payload
                    final String reply = "Hi Alice, I received your message. Since there were no exceptions thrown I know that your message was intact and secure. Lot's of love, Bob <3";
                    final byte[] replyPt = reply.getBytes(StandardCharsets.UTF_8);

                    // encrypt and send reply
                    bob.init(Cipher.ENCRYPT_MODE, key);
                    final byte[] replyCt = bob.doFinal(replyPt);
                    send("alice", replyCt);

                    // send IV
                    final byte[] iv = bob.getIV();
                    send("alice", iv);
                }
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}
