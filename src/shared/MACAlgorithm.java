package shared;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class MACAlgorithm {

    private byte[] keyBytes;
    private SecretKey key;
    
    // generates the 256-bit for MAC or reads it from a file
    public void generateOrReadSharedKey() {
        File macKeyFile = new File("Preshared-Data/mac.key");

        // check if the MAC key exists
        if (macKeyFile.exists()) {
            byte[] readBytes;

            // if so read the MAC key from file
            try {
                readBytes = Files.readAllBytes(macKeyFile.toPath());
            } catch (IOException e) {
                throw new IllegalStateException(e);
            }

            // decode the read data from Base64
            byte[] decoded = Base64.getDecoder().decode(readBytes);

            // create the key only if the key is 256 bits long
            if (decoded.length == 32) {
                keyBytes = decoded;
                key = new SecretKeySpec(keyBytes, "HmacSHA256");
                return;
            }
        }

        keyBytes = new byte[32];

        // generate a random 256 bit key
        try {
            SecureRandom.getInstanceStrong().nextBytes(keyBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }

        // create the key spec using HMAC SHA256
        key = new SecretKeySpec(keyBytes, "HmacSHA256");

        if (!macKeyFile.getParentFile().exists())
            macKeyFile.getParentFile().mkdirs();

        // write the key to a file
        try {
            Files.write(macKeyFile.toPath(), Base64.getEncoder().encode(keyBytes));
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    // calculates the MAC from a byte array of data
    public byte[] calculateMAC(byte[] data) {
        Mac mac;

        // initialise the MAC instance with HMAC SHA256 and the key
        try {
            mac = Mac.getInstance("HmacSHA256");
            mac.init(key);
        } catch (InvalidKeyException | NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }

        // calculuate and return the MAC of the data
        return mac.doFinal(data);
    }

}
