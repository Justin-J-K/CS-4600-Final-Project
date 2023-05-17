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
    
    public void generateOrReadSharedKey() {
        File macKeyFile = new File("Preshared-Data/mac.key");

        if (macKeyFile.exists()) {
            byte[] readBytes;

            try {
                readBytes = Files.readAllBytes(macKeyFile.toPath());
            } catch (IOException e) {
                throw new IllegalStateException(e);
            }

            byte[] decoded = Base64.getDecoder().decode(readBytes);

            if (decoded.length == 32) {
                keyBytes = decoded;
                key = new SecretKeySpec(keyBytes, "HmacSHA256");
                return;
            }
        }

        keyBytes = new byte[32];

        try {
            SecureRandom.getInstanceStrong().nextBytes(keyBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }

        key = new SecretKeySpec(keyBytes, "HmacSHA256");

        if (!macKeyFile.getParentFile().exists())
            macKeyFile.getParentFile().mkdirs();

        try {
            Files.write(macKeyFile.toPath(), Base64.getEncoder().encode(keyBytes));
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    public byte[] calculateMAC(byte[] data) {
        Mac mac;

        try {
            mac = Mac.getInstance("HmacSHA256");
            mac.init(key);
        } catch (InvalidKeyException | NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
        
        return mac.doFinal(data);
    }

}
