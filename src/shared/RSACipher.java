package shared;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

public class RSACipher {

    private RSAPrivateKey privateKey;
    private RSAPublicKey publicKey;

    public void generateKeyPair() {
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
    }

    public void transmitPublicKey(String partyName) {
        String path = "Transmitted-Data/" + partyName + ".pubkey";
        File keyFile = new File(path);

        // create the "Transmitted-Data" directory if it does not exist
        if (!keyFile.getParentFile().exists())
            keyFile.getParentFile().mkdirs();

        // write the public key to partyName.pubkey in X509 encoding
        try {
            Files.write(keyFile.toPath(), publicKey.getEncoded());
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    public void receivePublicKey(String otherParty) {
        String path = "Transmitted-Data/" + otherParty + ".pubkey";
        File keyFile = new File(path);

        // create the "Transmitted-Data" directory if it does not exist
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
        RSAPublicKey receivedKey;

        // try to get the public key from the bytes
        try {
            receivedKey = (RSAPublicKey) keyFactory.generatePublic(keySpec);
        } catch (InvalidKeySpecException e) {
            throw new IllegalStateException(e);
        }

        // check if key length is 2048 bits
        if (receivedKey.getModulus().bitLength() != 2048)
            throw new IllegalStateException("Invalid public key length: " + receivedKey.getModulus().bitLength());

        this.publicKey = receivedKey;
    }

    public RSAPublicKey getPublicKey() {
        return publicKey;
    }

}