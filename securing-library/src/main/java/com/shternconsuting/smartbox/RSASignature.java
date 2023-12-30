package com.shternconsuting.smartbox;

import java.security.*;
import java.util.Base64;

public class RSASignature {

    public static String sign(String data, PrivateKey privateKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(privateKey);
        sig.update(data.getBytes());
        return Base64.getEncoder().encodeToString(sig.sign());
    }

    public static boolean verify(String data, String signature, PublicKey publicKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(publicKey);
        sig.update(data.getBytes());
        return sig.verify(Base64.getDecoder().decode(signature));
    }

    public static void main(String[] args) {
        try {
        	String licenseJson = "{ \"companyName\" : \"ExampleCorp\", \"terminalId\":\"123-45-ABCF\"}";
            System.out.println("JSON Data: " + licenseJson);
            
            RSAKeyPairGenerator keyPairGenerator = new RSAKeyPairGenerator();
            String signature = sign(licenseJson, keyPairGenerator.getPrivateKey());
            System.out.println("Signature: " + signature);
            
            boolean isCorrect = verify(licenseJson, signature, keyPairGenerator.getPublicKey());
            System.out.println("Signature valid: " + isCorrect);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

