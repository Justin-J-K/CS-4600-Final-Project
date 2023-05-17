package shared;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AESCipher {
    
    private SecretKey key;
    private byte[] ivBytes;
    private IvParameterSpec iv;

    public void generateKeyAndIV() {
        KeyGenerator generator;
        
        try {
            generator = KeyGenerator.getInstance("AES");
            generator.init(128);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }

        key = generator.generateKey();

        ivBytes = new byte[16];

        try {
            SecureRandom.getInstanceStrong().nextBytes(ivBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }

        iv = new IvParameterSpec(ivBytes);
    }

    public byte[] getIvBytes() {
        return ivBytes;
    }

    public byte[] getKeyBytes() {
        return key.getEncoded();
    }

    public void setIvBytes(byte[] ivBytes) {
        if (ivBytes.length != 16)
            throw new IllegalStateException("Invalid IV length!");

        this.ivBytes = ivBytes;
        this.iv = new IvParameterSpec(ivBytes);
    }

    public void setKeyBytes(byte[] keyBytes) {
        if (keyBytes.length != 16)
            throw new IllegalStateException("Invalid AES key length!");

        this.key = new SecretKeySpec(keyBytes, "AES");
    }

    public byte[] encrypt(String message) {
        byte[] ciphertext;

        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key, iv);
            ciphertext = cipher.doFinal(message.getBytes());
        } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException
                | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
            throw new IllegalStateException(e);
        }

        return ciphertext;
    }

    public String decrypt(byte[] ciphertext) {
        String plaintext;

        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, key, iv);
            plaintext = new String(cipher.doFinal(ciphertext));
        } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException
                | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
            throw new IllegalStateException(e);
        }

        return plaintext;
    }

}
