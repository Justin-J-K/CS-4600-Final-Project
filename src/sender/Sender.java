package sender;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.Base64;

import shared.AESCipher;
import shared.MACAlgorithm;
import shared.RSACipher;

/*
 * The Sender program should be run first to setup the preshared MAC key and both
 * party's public and private keys.
 */
public class Sender {

    public static void main(String[] args) {

        /*
         * Assume both parties already know the MAC key and
         * each other's public keys used for RSA.
         */

        // assume the MAC key is preshared
        // get the preshared MAC key
        MACAlgorithm macAlgorithm = new MACAlgorithm();
        macAlgorithm.generateOrReadSharedKey();

        // generate RSA key pair and share the public key to the receiver
        RSACipher senderRsa = new RSACipher();
        senderRsa.generateOrReadKeyPair("sender");

        System.out.println("Run the Receiver program, then press any key to continue...");
        try {
            System.in.read();
        } catch (IOException e) {
            e.printStackTrace();
        }

        // read the shared public key from the receiver
        RSACipher receiverRsa = new RSACipher();
        receiverRsa.readSharedPublicKey("receiver");

        /*
         * At this point, the sender wants to send an encrypted message
         * to the receiver.
         */

        // generate the AES-128 key and initialization vector
        AESCipher aesCipher = new AESCipher();
        aesCipher.generateKeyAndIV();

        System.out.println("Generated AES Key and IV:");
        System.out.println("\tAES Key: " + Base64.getEncoder().encodeToString(aesCipher.getKeyBytes()));
        System.out.println("\tAES IV: " + Base64.getEncoder().encodeToString(aesCipher.getIvBytes()));

        // concatenate the 128-bit AES key and initialization vector
        byte[] aesKeyAndIv = concatenateBytes(aesCipher.getKeyBytes(), aesCipher.getIvBytes());

        // encrypt the concatenation of the key and IV with RSA ECB using the receiver's public key
        byte[] encryptedKeyIv = receiverRsa.encrypt(aesKeyAndIv);

        System.out.println("\nEncrypted AES Key and IV: " + Base64.getEncoder().encodeToString(encryptedKeyIv));

        // get the message to be encrypted and 
        // encrypt the message using AES-128 CBC
        String messageToEncrypt;
        File messageFile = new File("sender/message.txt");
        try {
            messageToEncrypt = new String(Files.readString(messageFile.toPath()));
        } catch (IOException e) {
            e.printStackTrace();
            return;
        }

        byte[] ciphertext = aesCipher.encrypt(messageToEncrypt);

        System.out.println("\nPlaintext: " + messageToEncrypt);
        System.out.println("Ciphertext: " + Base64.getEncoder().encodeToString(ciphertext));

        // concatenate the encrypted key and IV with the encrypted message
        byte[] keyIvAndCiphertext = concatenateBytes(encryptedKeyIv, ciphertext);

        // calculate the MAC of the encrypted key, IV and message
        byte[] mac = macAlgorithm.calculateMAC(keyIvAndCiphertext);

        System.out.println("\nMAC: " + Base64.getEncoder().encodeToString(mac));

        // concatenate the key, IV, and message with the MAC
        byte[] finalData = concatenateBytes(keyIvAndCiphertext, mac);

        // encode the final data into Base64
        byte[] finalDataBase64 = Base64.getEncoder().encode(finalData);

        System.out.println("\nTransmitted Data: " + new String(finalDataBase64));

        // transmit the Base64-encoded data to the receiver
        File transmitFile = new File("Transmitted-Data");
        try {
            Files.write(transmitFile.toPath(), finalDataBase64);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    // concatenate bytes1 and bytes2 into a new byte array
    private static byte[] concatenateBytes(byte[] bytes1, byte[] bytes2) {
        byte[] concatenated = new byte[bytes1.length + bytes2.length];

        System.arraycopy(bytes1, 0, concatenated, 0, bytes1.length);
        System.arraycopy(bytes2, 0, concatenated, bytes1.length, bytes2.length);

        return concatenated;
    }

}
