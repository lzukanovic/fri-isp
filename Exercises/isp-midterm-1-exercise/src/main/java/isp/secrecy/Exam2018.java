package isp.secrecy;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.X509EncodedKeySpec;

public class Exam2018 {
    public static void main(String[] args) throws Exception {

        final Environment env = new Environment();

        // RSA key pairs
        final KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        final KeyPair aliceRsaKP = kpg.generateKeyPair();
        final KeyPair bobRsaKP = kpg.generateKeyPair();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                /////
                //  Key Agreement (forward secrecy)
                ////

                // generate DH key pair
                final KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
                kpg.initialize(256);
                final KeyPair dhKP = kpg.generateKeyPair();

                // encrypt own DH PK using recipients RSA PK
                final Cipher rsaE = Cipher.getInstance("RSA/ECB/OAEPPadding");
                rsaE.init(Cipher.ENCRYPT_MODE, bobRsaKP.getPublic());
                final byte[] ctAlice = rsaE.doFinal(dhKP.getPublic().getEncoded());

                send("bob", ctAlice);

                // receive encrypted bob's DH PK
                final byte[] ctBob = receive("bob");
                final Cipher rsaD = Cipher.getInstance("RSA/ECB/OAEPPadding");
                rsaD.init(Cipher.DECRYPT_MODE, aliceRsaKP.getPrivate());
                final byte[] bobDh = rsaD.doFinal(ctBob);

                // get DH PK from bob
                final X509EncodedKeySpec keySpec = new X509EncodedKeySpec(bobDh);
                final ECPublicKey bobDhPK = (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(keySpec);

                // Run the agreement protocol
                final KeyAgreement dh = KeyAgreement.getInstance("ECDH");
                dh.init(dhKP.getPrivate());
                dh.doPhase(bobDhPK, true);

                // generate shared secret
                final byte[] sharedSecret = dh.generateSecret();
                print("Shared secret: %s", hex(sharedSecret));

                /////
                //  Secure the communication channel
                ////

                final SecretKeySpec aesKey = new SecretKeySpec(sharedSecret, 0, 16, "AES");
                final Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
                aes.init(Cipher.ENCRYPT_MODE, aesKey);
                final byte[] iv = aes.getIV();

                /////
                //  Time stamp protocol
                ////

                final String data = "Some message";

                // compute digest and send to bob
                final MessageDigest digestAlgorithm = MessageDigest.getInstance("SHA-256");
                final byte[] digest = digestAlgorithm.digest(data.getBytes(StandardCharsets.UTF_8));

                final byte[] ctDigest = aes.doFinal(digest);
                send("bob", ctDigest);
                send("bob", iv);
                print("Sent digest: %s", Agent.hex(digest));

                // get signature and timestamp from bob
                final byte[] ctSignature = receive("bob");
                final byte[] ivS = receive("bob");
                final byte[] ctTimestampBytes = receive("bob");
                final byte[] ivT = receive("bob");

                // decrypt both
                aes.init(Cipher.DECRYPT_MODE, aesKey, new GCMParameterSpec(128, ivS));
                final byte[] signature = aes.doFinal(ctSignature);
                aes.init(Cipher.DECRYPT_MODE, aesKey, new GCMParameterSpec(128, ivT));
                final byte[] timestampBytes = aes.doFinal(ctTimestampBytes);

                print("Got signature: " + Agent.hex(signature));
                // PRINT RECEIVED TIMESTAMP
                print("Got timestamp: " + Agent.hex(timestampBytes) + " --> " + bytesToLong(timestampBytes));

                // verify signature
                final byte[] timestampHash = digestAlgorithm.digest(timestampBytes);
                final byte[] document = concatByteArrays(digest, timestampHash);
                final Signature verifier = Signature.getInstance("SHA256withRSA");
                verifier.initVerify(bobRsaKP.getPublic());
                verifier.update(document);

                if (verifier.verify(signature)) {
                    print("Valid signature for document from Bob.");
                } else {
                    print("Invalid signature for document from Bob.");
                }
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                /////
                //  Key Agreement (forward secrecy)
                ////

                // receive encrypted alice's DH PK
                final byte[] ctAlice = receive("alice");
                final Cipher rsaD = Cipher.getInstance("RSA/ECB/OAEPPadding");
                rsaD.init(Cipher.DECRYPT_MODE, bobRsaKP.getPrivate());
                final byte[] aliceDh = rsaD.doFinal(ctAlice);

                // get DH public key from alice
                final X509EncodedKeySpec keySpec = new X509EncodedKeySpec(aliceDh);
                final ECPublicKey aliceDhPK = (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(keySpec);
                final ECParameterSpec dhParamSpec = aliceDhPK.getParams();

                // create own DH key pair
                final KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
                kpg.initialize(dhParamSpec);
                final KeyPair dhKP = kpg.generateKeyPair();

                // encrypt own DH PK using recipients RSA PK
                final Cipher rsaE = Cipher.getInstance("RSA/ECB/OAEPPadding");
                rsaE.init(Cipher.ENCRYPT_MODE, aliceRsaKP.getPublic());
                final byte[] ctBob = rsaE.doFinal(dhKP.getPublic().getEncoded());

                send("alice", ctBob);

                // Run the agreement protocol
                final KeyAgreement dh = KeyAgreement.getInstance("ECDH");
                dh.init(dhKP.getPrivate());
                dh.doPhase(aliceDhPK, true);

                // generate shared secret
                final byte[] sharedSecret = dh.generateSecret();
                print("  Shared secret: %s", hex(sharedSecret));

                /////
                //  Secure the communication channel
                ////

                final SecretKeySpec aesKey = new SecretKeySpec(sharedSecret, 0, 16, "AES");
                final Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");

                /////
                //  Time stamp protocol
                ////

                // get digest from alice
                final byte[] ctDigest = receive("alice");
                final byte[] ivAlice = receive("alice");
                aes.init(Cipher.DECRYPT_MODE, aesKey, new GCMParameterSpec(128, ivAlice));
                final byte[] digestAlice = aes.doFinal(ctDigest);
                print("  Got  digest: %s", Agent.hex(digestAlice));

                // generate timestamp
                final long timestamp = System.currentTimeMillis();
                final byte[] timestampBytes = longToBytes(timestamp);
                // generate timestamp hash
                final MessageDigest digestAlgorithm = MessageDigest.getInstance("SHA-256");
                final byte[] timestampHash = digestAlgorithm.digest(timestampBytes);

                print("Timestamp: " + timestamp);
                print("Timestamp (hex): " + Agent.hex(timestampBytes));

                // concatenate and sign
                final byte[] concat = concatByteArrays(digestAlice, timestampHash);
                final Signature signer = Signature.getInstance("SHA256withRSA");
                signer.initSign(bobRsaKP.getPrivate());
                signer.update(concat);
                final byte[] signature = signer.sign();
                print("Signature: " + Agent.hex(signature));

                // send signature and timestamp
                aes.init(Cipher.ENCRYPT_MODE, aesKey);
                final byte[] ctSignature = aes.doFinal(signature);
                final byte[] ivS = aes.getIV();

                aes.init(Cipher.ENCRYPT_MODE, aesKey);
                final byte[] ctTimestamp = aes.doFinal(timestampBytes);
                final byte[] ivT = aes.getIV();

                send("alice", ctSignature);
                send("alice", ivS);
                send("alice", ctTimestamp);
                send("alice", ivT);

                print("Sent encrypted signature and timestamp.");
            }
        });

        env.connect("alice", "bob");
        env.start();
    }

    public static byte[] concatByteArrays(byte[] a, byte[] b) throws IOException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
        outputStream.write(a);
        outputStream.write(b);

        return outputStream.toByteArray( );
    }

    public static byte[] longToBytes(long x) {
        ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
        buffer.putLong(x);
        return buffer.array();
    }

    public static long bytesToLong(byte[] bytes) {
        ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
        buffer.put(bytes);
        buffer.flip(); //need flip
        return buffer.getLong();
    }
}
