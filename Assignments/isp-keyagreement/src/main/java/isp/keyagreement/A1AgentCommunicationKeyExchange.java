package isp.keyagreement;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.X509EncodedKeySpec;

/*
 * Implement a key exchange between Alice and Bob using public-key encryption.
 * Once the shared secret is established, send an encrypted message from Alice to Bob using
 * AES in GCM.
 */
public class A1AgentCommunicationKeyExchange {
    public static void main(String[] args) {
        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                System.out.println("Starting key exchange..");
                // Generate key pair
                final KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");
                kpg.initialize(2048);
                final KeyPair keyPair = kpg.generateKeyPair();

                // send "PK" to bob ("PK": A = g^a, "SK": a)
                send("bob", keyPair.getPublic().getEncoded());
                print("My contribution: A = g^a = %s", hex(keyPair.getPublic().getEncoded()));

                // Get PK from bob
                final X509EncodedKeySpec keySpec = new X509EncodedKeySpec(receive("bob"));
                final DHPublicKey bobPK = (DHPublicKey) KeyFactory.getInstance("DH").generatePublic(keySpec);

                // Run the agreement protocol
                final KeyAgreement dh = KeyAgreement.getInstance("DH");
                dh.init(keyPair.getPrivate());
                dh.doPhase(bobPK, true);

                // Generate a shared AES key
                final byte[] sharedSecret = dh.generateSecret();
                print("Shared secret: g^ab = B^a = %s", hex(sharedSecret));
                // By default, the shared secret will be 32 bytes long, but our cipher requires keys of length 16 bytes
                final SecretKeySpec aesKey = new SecretKeySpec(sharedSecret, 0, 16, "AES");

                System.out.println("Starting message exchange..");

                // Generate cipher text and send
                final Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
                aes.init(Cipher.ENCRYPT_MODE, aesKey);

                String message = "Hey, Bob!";
                final byte[] ct = aes.doFinal(message.getBytes(StandardCharsets.UTF_8));
                final byte[] iv = aes.getIV();
                send("bob", ct);
                send("bob", iv);
                print("Sent message to Bob.");
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                // Get PK from alice
                final X509EncodedKeySpec keySpec = new X509EncodedKeySpec(receive("alice"));
                final DHPublicKey alicePK = (DHPublicKey) KeyFactory.getInstance("DH").generatePublic(keySpec);
                final DHParameterSpec dhParamSpec = alicePK.getParams();

                // Create your own DH key pair
                final KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");
                kpg.initialize(dhParamSpec);
                final KeyPair keyPair = kpg.generateKeyPair();
                send("alice", keyPair.getPublic().getEncoded());
                print("  My contribution: B = g^b = %s", hex(keyPair.getPublic().getEncoded()));

                // Run the agreement protocol
                final KeyAgreement dh = KeyAgreement.getInstance("DH");
                dh.init(keyPair.getPrivate());
                dh.doPhase(alicePK, true);

                // Generate a shared AES key
                final byte[] sharedSecret = dh.generateSecret();
                print("  Shared secret: g^ab = A^b = %s", hex(sharedSecret));
                // By default, the shared secret will be 32 bytes long, but our cipher requires keys of length 16 bytes
                final SecretKeySpec aesKey = new SecretKeySpec(sharedSecret, 0, 16, "AES");

                // Receive message from Alice
                final byte[] ct = receive("alice");
                final byte[] iv = receive("alice");

                // Decrypt message
                final Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
                final GCMParameterSpec gcmParamSpec = new GCMParameterSpec(128, iv);
                aes.init(Cipher.DECRYPT_MODE, aesKey, gcmParamSpec);
                final byte[] pt = aes.doFinal(ct);
                print("Received message from Alice: '%s'", new String(pt));
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}