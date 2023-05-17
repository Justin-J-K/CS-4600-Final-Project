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

    // generate the key and IV that will be used with AES encryption and decryption
    public void generateKeyAndIV() {
        KeyGenerator generator;
        
        // initialise a key generator for AES-128
        try {
            generator = KeyGenerator.getInstance("AES");
            generator.init(128);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }

        // generate a 128-bit key
        key = generator.generateKey();

        ivBytes = new byte[16];

        // generate a 128-bit initialization vector
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

    // set the IV for the AES cipher instance
    public void setIvBytes(byte[] ivBytes) {
        this.ivBytes = ivBytes;
        this.iv = new IvParameterSpec(ivBytes);
    }

    // set the key for AES cipher instance
    public void setKeyBytes(byte[] keyBytes) {
        this.key = new SecretKeySpec(keyBytes, "AES");
    }

    // encrypt the message using AES-128 CBC
    public byte[] encrypt(String message) {
        byte[] ciphertext;

        try {
            // initialise the cipher with AES, key, and IV
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key, iv);
            // encrypt the message using the key and IV
            ciphertext = cipher.doFinal(message.getBytes());
        } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException
                | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
            throw new IllegalStateException(e);
        }

        return ciphertext;
    }

    // decrypt the ciphertext using AES-128 CBC
    public String decrypt(byte[] ciphertext) {
        String plaintext;

        try {
            // initialise cipher with AES, key, and IV
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, key, iv);
            // decrypt the ciphertext using the key and IV
            plaintext = new String(cipher.doFinal(ciphertext));
        } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException
                | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
            throw new IllegalStateException(e);
        }

        return plaintext;
    }

}
