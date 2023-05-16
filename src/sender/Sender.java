package sender;

import shared.RSACipher;

public class Sender {
    
    public static void main(String[] args) {
        RSACipher rsaCipher = new RSACipher();
        rsaCipher.generateKeyPair();
        rsaCipher.transmitPublicKey("sender");

        RSACipher receive = new RSACipher();
        receive.receivePublicKey("sender");

        System.out.println(rsaCipher.getPublicKey());
        System.out.println(receive.getPublicKey());

        System.out.println(rsaCipher.getPublicKey().equals(receive.getPublicKey()));
    }

}
