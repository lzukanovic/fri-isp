package isp.rsa;

import fri.isp.Agent;

import javax.crypto.Cipher;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.RSAPrivateCrtKeySpec;

/**
 * - Try to set the RSA modulus size manually
 * FIXME: ---> We use the initialize() function of the KeyPairGenerator instance. The default size is 2048 bits.
 *
 * - Try setting padding to NoPadding. Encrypt a message and decrypt it. Is the
 * decrypted text the same as the original plaint text? Why?
 * FIXME: ---> They are not the same, because with the parameter 'NoPadding' we are expected to handle/add the padding
 *             ourselves. So all the 0 bytes from the decoded plaintext need to be removed to just get the original message.
 *
 * FIXME: This could also be because of the requirement (not sure if because of library) for the message length to be
 *        equal to key/modulus size.
 *
 *  Some helpful resources on this topic:
 *  - https://stackoverflow.com/questions/52442742/rsa-ecb-nopadding-decryption-returning-null-characters
 *  - https://crypto.stackexchange.com/questions/15174/is-it-true-that-for-rsa-with-no-padding-the-length-of-data-must-be-equal-to-the
 *  - https://gist.github.com/ukdave/13fe13e1063babfd47896a2044d5ad18
 */
public class RSAExample {
    public static void main(String[] args) throws Exception {
        // Set RSA cipher specs:
        //  - Set mode to ECB: each block is encrypted independently
        //  - Set padding to OAEP (preferred mode);
        //    alternatives are PKCS1Padding (the default) and NoPadding ("textbook" RSA)

        // ECB should not be used in block ciphers, but with RSA it is fine
        // OAEP Padding - only one that should be used!
        final String algorithm = "RSA/ECB/NoPadding";
        final String message = "A test message.";
        final byte[] pt = message.getBytes(StandardCharsets.UTF_8);
        final BigInteger ptInt = new BigInteger(pt);

        System.out.println("Message: " + message);
        System.out.println("PT: " + Agent.hex(pt));

        // STEP 1: Bob creates his public and private key pair.
        // Alice receives Bob's public key.
        final KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        // manually set key/modulus size
        kpg.initialize(1024);
        final KeyPair bobKP = kpg.generateKeyPair();
        System.out.println("-----");
        System.out.println("Private key: " + bobKP.getPrivate());
        System.out.println("Public key: " + bobKP.getPublic());

        // Additional destructed parameters
        System.out.println("-----");
        KeyFactory keyFac = KeyFactory.getInstance("RSA");
        RSAPrivateCrtKeySpec pkSpec = keyFac.getKeySpec(bobKP.getPrivate(), RSAPrivateCrtKeySpec.class);
        System.out.println("Prime exponent p: " + pkSpec.getPrimeExponentP());
        System.out.println("Prime exponent q: " + pkSpec.getPrimeExponentQ());
        System.out.println("Modulus: " + pkSpec.getModulus());
        System.out.println("Private exponent: " + pkSpec.getPrivateExponent());
        System.out.println("Public exponent: " + pkSpec.getPublicExponent());
        System.out.println("Calculated pq: " + pkSpec.getPrimeExponentP().multiply(pkSpec.getPrimeExponentQ()));
        System.out.println("Calculated CT: " + Agent.hex(ptInt.modPow(pkSpec.getPublicExponent(), pkSpec.getModulus()).toByteArray()));
        System.out.println("-----");

        // STEP 2: Alice creates Cipher object defining cipher algorithm.
        // She then encrypts the clear-text and sends it to Bob.
        final Cipher rsaEnc = Cipher.getInstance(algorithm);
        rsaEnc.init(Cipher.ENCRYPT_MODE, bobKP.getPublic());
        final byte[] ct = rsaEnc.doFinal(pt);

        // STEP 3: Display cipher text in hex. This is what an attacker would see,
        // if she intercepted the message.
        System.out.println("CT: " + Agent.hex(ct));

        // STEP 4: Bob decrypts the cipher text using the same algorithm and his private key.
        final Cipher rsaDec = Cipher.getInstance(algorithm);
        rsaDec.init(Cipher.DECRYPT_MODE, bobKP.getPrivate());
        final byte[] decryptedText = rsaDec.doFinal(ct);

        // STEP 5: Bob displays the clear text
        System.out.println("PT: " + Agent.hex(decryptedText));
        final String message2 = new String(decryptedText, StandardCharsets.UTF_8);
        System.out.println("Message: " + message2);
    }
}
