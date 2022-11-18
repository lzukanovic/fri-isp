package isp.rsa;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

/**
 * Assuming Alice and Bob know each other's public key, secure the channel using a
 * RSA. Then exchange ten messages between Alice and Bob.
 *
 * (The remaining assignment(s) can be found in the isp.steganography.ImageSteganography
 * class.)
 */
public class A1AgentCommunicationRSA {
    public static void main(String[] args) throws Exception {

        // Create two public-secret key pairs
        final KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        final KeyPair aliceKP = kpg.generateKeyPair();
        final KeyPair bobKP = kpg.generateKeyPair();
        final int numberOfExchanges = 5;
        final String algorithm = "RSA/ECB/OAEPPadding";

        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                for (int i = 0; i < numberOfExchanges; i++) {
                    System.out.println("=== Message exchange no. " + (i+1) + " ===");
                    final String message = "A message for Bob.";
                    final byte[] pt = message.getBytes(StandardCharsets.UTF_8);

                    final Cipher rsa = Cipher.getInstance(algorithm);
                    rsa.init(Cipher.ENCRYPT_MODE, bobKP.getPublic());
                    final byte[] ct = rsa.doFinal(pt);

                    print("Sent message to Bob.");
                    send("bob", ct);

                    final byte[] ctReply = receive("bob");
                    rsa.init(Cipher.DECRYPT_MODE, aliceKP.getPrivate());
                    final byte[] ptReply = rsa.doFinal(ctReply);
                    print("Got a reply back from Bob '%s'", new String(ptReply));
                }
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                for (int i = 0; i < numberOfExchanges; i++) {
                    final byte[] ct = receive("alice");

                    final Cipher rsa = Cipher.getInstance(algorithm);
                    rsa.init(Cipher.DECRYPT_MODE, bobKP.getPrivate());
                    final byte[] pt = rsa.doFinal(ct);

                    print("Got message '%s'", new String(pt));

                    final String reply = "Got your message, thanks!";
                    rsa.init(Cipher.ENCRYPT_MODE, aliceKP.getPublic());
                    final byte[] ctReply = rsa.doFinal(reply.getBytes(StandardCharsets.UTF_8));

                    print("Sent reply to Alice.");
                    send("alice", ctReply);
                }
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}
