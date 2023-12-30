package com.shternconsuting.smartbox;

import java.security.*;

public class RSAKeyPairGenerator {
    private PrivateKey privateKey;
    private PublicKey publicKey;

    public RSAKeyPairGenerator() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair pair = keyGen.generateKeyPair();
        this.privateKey = pair.getPrivate();
        this.publicKey = pair.getPublic();
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }
    
    public static void main(String[] args) {
        try {
            RSAKeyPairGenerator keyPairGenerator = new RSAKeyPairGenerator();
            System.out.println("Public Key: " + keyPairGenerator.getPublicKey());
            System.out.println("Private Key: " + 
            		java.util.Base64.getEncoder().encodeToString(keyPairGenerator.getPrivateKey().getEncoded()));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }
}

