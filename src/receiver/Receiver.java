package receiver;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.Base64;

import shared.AESCipher;
import shared.MACAlgorithm;
import shared.RSACipher;

public class Receiver {
    
    public static void main(String[] args) {
        
        /*
         * Assume both parties already know the MAC key and
         * each other's public keys used for RSA.
         */

        // assume the MAC key is preshared
        // get the preshared MAC key
        MACAlgorithm macAlgorithm = new MACAlgorithm();
        macAlgorithm.generateOrReadSharedKey();

        // generate RSA key pair and share the public key to the sender
        RSACipher receiverRsa = new RSACipher();
        receiverRsa.generateOrReadKeyPair("receiver");

        System.out.println("Now continue the Sender program, then press any key to continue...");
        try {
            System.in.read();
        } catch (IOException e) {
            e.printStackTrace();
        }

        // read the shared public key from the sender
        RSACipher senderRsa = new RSACipher();
        senderRsa.readSharedPublicKey("sender");

        /*
         * At this point, the sender has sent the encrypted message with AES key,
         * message, and MAC.
         */

        // receive the Base64-encoded transmitted data from the sender
        byte[] receivedDataBase64;
        File dataFile = new File("Transmitted-Data");
        try {
            receivedDataBase64 = Files.readAllBytes(dataFile.toPath());
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }

        System.out.println("Received Data: " + new String(receivedDataBase64));

        // decode the transmitted data from Base64
        byte[] receivedData = Base64.getDecoder().decode(receivedDataBase64);

        // separate the received data into encrypted key and IV, and encrypted message; and the MAC
        byte[] keyIvAndCiphertext = Arrays.copyOfRange(receivedData, 0, receivedData.length - 32);
        byte[] mac = Arrays.copyOfRange(receivedData, receivedData.length - 32, receivedData.length);

        // calculate the MAC from the key, IV, and ciphertext
        byte[] calculatedMac = macAlgorithm.calculateMAC(keyIvAndCiphertext);

        // compare the calculate MAC and the received MAC
        boolean sameMac = Arrays.equals(mac, calculatedMac);

        System.out.println("\nReceived MAC: " + Base64.getEncoder().encodeToString(mac));
        System.out.println("Calculated MAC: " + Base64.getEncoder().encodeToString(calculatedMac));
        System.out.println("Authenticity & Integrity: " + (sameMac ? "GOOD" : "BAD"));

        // separate the key, IV, and ciphertext into key and IV; and ciphertext
        byte[] encryptedKeyIv = Arrays.copyOfRange(keyIvAndCiphertext, 0, 256);
        byte[] ciphertext = Arrays.copyOfRange(keyIvAndCiphertext, 256, keyIvAndCiphertext.length);

        System.out.println("\nEncrypted AES Key and IV: " + Base64.getEncoder().encodeToString(encryptedKeyIv));

        // decrypt the encrypted key and IV using RSA with the receiver's private key
        byte[] aesKeyAndIv = receiverRsa.decrypt(encryptedKeyIv);

        // separate the key and IV
        byte[] aesKey = Arrays.copyOfRange(aesKeyAndIv, 0, 16);
        byte[] iv = Arrays.copyOfRange(aesKeyAndIv, 16, 32);

        System.out.println("\nDecrypted AES Key and IV:");
        System.out.println("\tAES Key: " + Base64.getEncoder().encodeToString(aesKey));
        System.out.println("\tAES IV: " + Base64.getEncoder().encodeToString(iv));

        AESCipher aesCipher = new AESCipher();
        aesCipher.setKeyBytes(aesKey);
        aesCipher.setIvBytes(iv);   

        // decrypt the ciphertext using the AES key and IV
        String plaintext = aesCipher.decrypt(ciphertext);

        System.out.println("\nCiphertext: " + Base64.getEncoder().encodeToString(ciphertext));
        System.out.println("Plaintext: " + plaintext);

    }

}
