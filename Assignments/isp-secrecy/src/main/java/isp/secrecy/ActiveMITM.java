package isp.secrecy;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Arrays;

public class ActiveMITM {
    public static void main(String[] args) throws Exception {
        // David and FMTP server both know the same shared secret key
        final Key key = KeyGenerator.getInstance("AES").generateKey();

        final Environment env = new Environment();

        env.add(new Agent("david") {
            @Override
            public void task() throws Exception {
                final String message = "prf.denis@fri.si\n" +
                        "david@fri.si\n" +
                        "Some ideas for the exam\n\n" +
                        "Hi! Find attached <some secret stuff>!";

                final Cipher aes = Cipher.getInstance("AES/CBC/PKCS5Padding");
                aes.init(Cipher.ENCRYPT_MODE, key);
                final byte[] ct = aes.doFinal(message.getBytes(StandardCharsets.UTF_8));
                final byte[] iv = aes.getIV();
                print("sending: '%s' (%s)", message, hex(ct));
                send("server", ct);
                send("server", iv);
            }
        });

        env.add(new Agent("student") {
            @Override
            public void task() throws Exception {
                byte[] bytes = receive("david");
                final byte[] iv = receive("david");
                print(" IN: %s", hex(bytes));

                System.out.println("attacking....");
                final int BLOCK_SIZE_BYTES = 16;
                final String originalEmail = "prf.denis@fri.si";
                byte[] originalEmailBytes = originalEmail.getBytes(StandardCharsets.UTF_8);
                // add 3 spaces at the end to make it the same length as the original
                // "Any preceding or trailing spaces on any line are removed before processing
                // [...] it would have made no difference."
                final String newEmail = "isp@gmail.com   ";
                byte[] newEmailBytes = newEmail.getBytes(StandardCharsets.UTF_8);

                // _i here is considered the block we want to change, in this case the first block
                // plaintext block that we know
                byte[] p_i = Arrays.copyOfRange(originalEmailBytes, 0, BLOCK_SIZE_BYTES);
                // our block that we want to inject
                byte[] x_i = Arrays.copyOfRange(newEmailBytes, 0, BLOCK_SIZE_BYTES);

                print("p_i: " + hex(p_i));
                print("iv:  " + hex(iv));
                print("x_i: " + hex(x_i));

                // the goal is to manipulate the cipher text block at index i-1
                // p_i = D(c_i, key) XOR c_{i-1}
                byte[] d_i = new byte[BLOCK_SIZE_BYTES];
                for (int j = 0; j < BLOCK_SIZE_BYTES; j++) {
                    d_i[j] = (byte) (iv[j] ^ p_i[j]);
                }

                // we manipulate the cipher text block at index i-1
                // in this special case, because we are on the first cipher block,
                // we manipulate the IV
                for (int j = 0; j < BLOCK_SIZE_BYTES; j++) {
                    iv[j] = (byte) (d_i[j] ^ x_i[j]);
                }

                System.out.println("done!");
                print("OUT: %s", hex(bytes));
                send("server", bytes);
                send("server", iv);
            }
        });

        env.add(new Agent("server") {
            @Override
            public void task() throws Exception {
                final byte[] ct = receive("david");
                final byte[] iv = receive("david");
                final Cipher aes = Cipher.getInstance("AES/CBC/PKCS5Padding");
                aes.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
                final byte[] pt = aes.doFinal(ct);
                final String message = new String(pt, StandardCharsets.UTF_8);

                print("got: '%s' (%s)", message, hex(ct));
            }
        });

        env.mitm("david", "server", "student");
        env.start();
    }
}
