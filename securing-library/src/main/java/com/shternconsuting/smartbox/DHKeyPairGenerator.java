package com.shternconsuting.smartbox;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.PrivateKey;

public class DHKeyPairGenerator {

    private PublicKey publicKey;
    private PrivateKey privateKey;
    
    private static int KEY_STRENGTH = 2048;

    public DHKeyPairGenerator() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH");
        keyGen.initialize(KEY_STRENGTH);
        KeyPair pair = keyGen.generateKeyPair();
        this.privateKey = pair.getPrivate();
        this.publicKey = pair.getPublic();
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public static void main(String[] args) {
        try {
            DHKeyPairGenerator keyPairGenerator = new DHKeyPairGenerator();
            System.out.println("Public Key: " + keyPairGenerator.getPublicKey());
            System.out.println("Private Key: " + 
            		java.util.Base64.getEncoder().encodeToString(keyPairGenerator.getPrivateKey().getEncoded()));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }
}
