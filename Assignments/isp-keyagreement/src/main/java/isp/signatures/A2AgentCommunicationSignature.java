package isp.signatures;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.KeyGenerator;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;

/*
 * Assuming Alice and Bob know each other's public key, provide integrity and non-repudiation
 * to exchanged messages with ECDSA. Then exchange ten signed messages between Alice and Bob.
 */
public class A2AgentCommunicationSignature {
    public static void main(String[] args) throws Exception {
        final Environment env = new Environment();

        final int numOfExchanges = 10;
        final String signingAlgorithm = "SHA256withECDSA";
        final String keyAlgorithm = "EC";

        // Create key pairs
        final KeyPair aliceKey = KeyPairGenerator.getInstance(keyAlgorithm).generateKeyPair();
        final KeyPair bobKey = KeyPairGenerator.getInstance(keyAlgorithm).generateKeyPair();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                // repeat 10 times
                for (int i = 0; i < numOfExchanges; i++) {
                    System.out.printf("\n=== Signed documents exchange no. %d ===\n", i+1);
                    // create a message and sign it
                    final String document = "Signed message for Bob.";
                    final Signature signer = Signature.getInstance(signingAlgorithm);
                    signer.initSign(aliceKey.getPrivate());
                    signer.update(document.getBytes(StandardCharsets.UTF_8));
                    final byte[] signature = signer.sign();

                    // and send the message, signature pair to bob
                    print("Sent document and signature to Bob.");
                    send("bob", document.getBytes(StandardCharsets.UTF_8));
                    send("bob", signature);

                    // receive the message signature pair
                    final byte[] documentB = receive("bob");
                    final byte[] signatureB = receive("bob");

                    // verify the signature
                    final Signature verifier = Signature.getInstance(signingAlgorithm);
                    verifier.initVerify(bobKey.getPublic());
                    verifier.update(documentB);

                    if (verifier.verify(signatureB)) {
                        print("Valid signature for document from Bob.");
                    } else {
                        print("Invalid signature for document from Bob.");
                    }
                }
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                for (int i = 0; i < numOfExchanges; i++) {
                    // receive the message signature pair
                    final byte[] documentA = receive("alice");
                    final byte[] signatureA = receive("alice");

                    // verify the signature
                    final Signature verifier = Signature.getInstance(signingAlgorithm);
                    verifier.initVerify(aliceKey.getPublic());
                    verifier.update(documentA);

                    if (verifier.verify(signatureA)) {
                        print("Valid signature for document from Alice.");
                    } else {
                        print("Invalid signature for document from Alice.");
                    }

                    // create a message and sign it
                    final String document = "Signed message for Alice.";
                    final Signature signer = Signature.getInstance(signingAlgorithm);
                    signer.initSign(bobKey.getPrivate());
                    signer.update(document.getBytes(StandardCharsets.UTF_8));
                    final byte[] signature = signer.sign();

                    // and send the message, signature pair to alice
                    print("Sent reply document and signature to Alice.");
                    send("alice", document.getBytes(StandardCharsets.UTF_8));
                    send("alice", signature);
                }
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}