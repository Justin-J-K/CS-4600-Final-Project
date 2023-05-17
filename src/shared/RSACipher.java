package shared;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class RSACipher {

    private RSAPrivateKey privateKey;
    private RSAPublicKey publicKey;

    public void generateOrReadKeyPair(String partyName) {
        String publicPath = "Preshared-Data/" + partyName + ".pubkey";
        String privatePath = partyName + "/" + partyName + ".privkey";
        File publicKeyFile = new File(publicPath);
        File privateKeyFile = new File(privatePath);

        // if keys already exist read them instead of generating new ones
        if (publicKeyFile.exists()) {
            byte[] publicKeyBytes;

            try {
                publicKeyBytes = Files.readAllBytes(publicKeyFile.toPath());
            } catch (IOException e) {
                throw new IllegalStateException(e);
            }

            byte[] privateKeyBytes;

            try {
                privateKeyBytes = Files.readAllBytes(privateKeyFile.toPath());
            } catch (IOException e) {
                throw new IllegalStateException(e);
            }

            KeyFactory keyFactory;

            // get an instance of a key factory for RSA
            try {
                keyFactory = KeyFactory.getInstance("RSA");
            } catch (NoSuchAlgorithmException e) {
                throw new IllegalStateException(e);
            }

            // create a new X509 encoded key spec using the public key bytes
            EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);

            // try to get the public key from the bytes
            try {
                publicKey = (RSAPublicKey) keyFactory.generatePublic(publicKeySpec);
            } catch (InvalidKeySpecException e) {
                throw new IllegalStateException(e);
            }

            // create a new PKCS8 encoded key spec using the private key bytes
            EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes, "RSA");

            // try to get the privateKey key from the bytes
            try {
                privateKey = (RSAPrivateKey) keyFactory.generatePrivate(privateKeySpec);
            } catch (InvalidKeySpecException e) {
                throw new IllegalStateException(e);
            }

            return;
        }

        KeyPairGenerator rsaGenerator;

        // get the RSA key generator
        try {
            rsaGenerator = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }

        // use 2048 bit keys for RSA
        rsaGenerator.initialize(2048);

        // generate the RSA public and private keys
        KeyPair keyPair = rsaGenerator.generateKeyPair();

        privateKey = (RSAPrivateKey) keyPair.getPrivate();
        publicKey = (RSAPublicKey) keyPair.getPublic();

        // create the "Preshared-Data" directory if it does not exist
        if (!publicKeyFile.getParentFile().exists())
            publicKeyFile.getParentFile().mkdirs();

        // write the public key to partyName.pubkey in X509 encoding
        try {
            Files.write(publicKeyFile.toPath(), publicKey.getEncoded());
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }

        // create the party name directory if it does not exist
        if (!privateKeyFile.getParentFile().exists())
            privateKeyFile.getParentFile().mkdirs();

        // write the private key to partyName.privkey in X509 encoding
        try {
            Files.write(privateKeyFile.toPath(), privateKey.getEncoded());
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    public void readSharedPublicKey(String otherParty) {
        String path = "Preshared-Data/" + otherParty + ".pubkey";
        File keyFile = new File(path);

        // create the "Preshared-Data" directory if it does not exist
        if (!keyFile.getParentFile().exists())
            keyFile.getParentFile().mkdirs();

        byte[] publicKeyBytes;

        // read the public key from otherParty.pubkey
        try {
            publicKeyBytes = Files.readAllBytes(keyFile.toPath());
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }

        KeyFactory keyFactory;

        // get an instance of a key factory for RSA
        try {
            keyFactory = KeyFactory.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }

        // create a new X509 encoded key spec using the public key bytes
        EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);

        // try to get the public key from the bytes
        try {
            publicKey = (RSAPublicKey) keyFactory.generatePublic(keySpec);
        } catch (InvalidKeySpecException e) {
            throw new IllegalStateException(e);
        }
    }

    public RSAPublicKey getPublicKey() {
        return publicKey;
    }

    public RSAPrivateKey getPrivateKey() {
        return privateKey;
    }

    public byte[] encrypt(byte[] plaintext) {
        byte[] ciphertext;

        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            ciphertext = cipher.doFinal(plaintext);
        } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException
                | BadPaddingException e) {
            throw new IllegalStateException(e);
        }

        return ciphertext;
    }

    public byte[] decrypt(byte[] ciphertext) {
        byte[] plaintext;

        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            plaintext = cipher.doFinal(ciphertext);
        } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException
                | BadPaddingException e) {
            throw new IllegalStateException(e);
        }

        return plaintext;
    }

}