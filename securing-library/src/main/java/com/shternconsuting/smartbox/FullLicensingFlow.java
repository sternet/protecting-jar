package com.shternconsuting.smartbox;


import java.io.FileOutputStream;
import java.io.FileWriter;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.json.JSONObject;

public class FullLicensingFlow {
	
	private static String workingDirectory = System.getProperty("user.dir");
    

	public static void saveKeyPair(KeyPair keyPair, String label, String keyPath) {
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        try {
            // Save the public key
            try (FileWriter out = new FileWriter(keyPath + "/" + label + "-public.key")) {
                out.write(Base64.getEncoder().encodeToString(publicKey.getEncoded()));
            }

            // Save the private key
            try (FileWriter out = new FileWriter(keyPath + "/" + label + "-private.key")) {
                out.write(Base64.getEncoder().encodeToString(privateKey.getEncoded()));
            }
		} catch (Exception e) {
			e.printStackTrace();
		}
    }
	
	public static void saveLicense(String license, String path) {
        try {
            try (FileWriter out = new FileWriter(path + "/license.json")) {
                out.write(license);
            }
		} catch (Exception e) {
			e.printStackTrace();
		}
    }
	
	private static KeyPair generateRSAKeyPair(String label) throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        saveKeyPair(keyPair, label, workingDirectory + "/../libraries/");
        return keyPair;
    }
	
	public static String hashWithSHA256(String input) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return Base64.getEncoder().encodeToString(md.digest(input.getBytes()));
    }
	
	public static String encrypt(String plainText, PublicKey publicKey) throws Exception {
	    Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
	    cipher.init(Cipher.ENCRYPT_MODE, publicKey);
	    return Base64.getEncoder().encodeToString(cipher.doFinal(plainText.getBytes()));
	}
	
	public static String GenerateLincese() {
		 try {
			// Create License Information
	        JSONObject licenseInfo = new JSONObject();
	        licenseInfo.put("companyName", "Big Customer");
	        licenseInfo.put("licenseType", "Terminal Usage");
	        licenseInfo.put("expiryDate", "2024-12-31");
	        licenseInfo.put("terminalId", "123-45-ABGC");
	        
	        String licenseInfoJSON = licenseInfo.toString(4);
	        System.out.println("License Info: " + licenseInfoJSON);
	        
	        String licenseInfoHash = hashWithSHA256(licenseInfoJSON);
	        System.out.println("License Info hash: " + licenseInfoHash);
	        
	        KeyPair smartboxCompanyKey = generateRSAKeyPair("smartbox");
	        KeyPair terminalKey = generateRSAKeyPair("terminal");
	        
	        // Sign the License Information
	        String signature = RSASignature.sign(licenseInfoJSON, smartboxCompanyKey.getPrivate());
	
	        // Encrypt the hash using Terminal Public key
	        String encryptedHash = encrypt(licenseInfoHash, terminalKey.getPublic());
	
	        // Create the License Code
	        JSONObject licenseCode = new JSONObject();
	        licenseCode.put("licenseInfo", licenseInfo);
	        licenseCode.put("ehash", encryptedHash);
	        licenseCode.put("signature", signature);
	        
	        String licenseCodeJSON = licenseCode.toString(4);
	        System.out.println("License: " + licenseCodeJSON);	        

	        saveLicense(licenseCodeJSON, workingDirectory + "/../libraries/");	        
	        
	        return licenseInfoHash;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
	}
	
	private static byte[] hkdf(byte[] input, int length) {
        HKDFBytesGenerator hkdf = new HKDFBytesGenerator(new SHA256Digest());
        hkdf.init(new HKDFParameters(input, null, null));
        byte[] okm = new byte[length];
        hkdf.generateBytes(okm, 0, length);
        return okm;
    }
	
	public static SecretKey createAESKeyFromBytes(byte[] aesKeyBytes) {
        return new SecretKeySpec(aesKeyBytes, "AES");
    }
	
	public static byte[] encryptBinary(byte[] data, SecretKey key) throws Exception {
	    Cipher cipher = Cipher.getInstance("AES");
	    cipher.init(Cipher.ENCRYPT_MODE, key);
	    return cipher.doFinal(data);
	}

	
	public static void encryptJarFile(String jarFilePath, String encryptedJarFilePath, SecretKey key) throws Exception {
	    // Read the JAR file
	    byte[] fileData = Files.readAllBytes(Paths.get(jarFilePath));

	    // Encrypt the file data
	    byte[] encryptedData = encryptBinary(fileData, key);

	    // Write the encrypted data to a new file
	    try (FileOutputStream fos = new FileOutputStream(encryptedJarFilePath)) {
	        fos.write(encryptedData);
	    }
	}
	
	public static void main(String[] args) {
        try {
        	String keyMaterial = GenerateLincese();
        	
        	// Derive a 256-bit key (32 bytes) using HKDF
        	byte[] keyHash = Base64.getDecoder().decode(keyMaterial);
            byte[] aesKeyMaterial = hkdf(keyHash, 32);
            SecretKey aesKey = createAESKeyFromBytes(aesKeyMaterial);
            System.out.println("Generated AES key from the key material: " + keyMaterial);
            
            String workingDirectory = System.getProperty("user.dir");
            System.out.println("Current working directory: " + workingDirectory);
            
            String jarFilePath = "../libraries/sensitive-code.jar";
            String encryptedJarFilePath = "../libraries/sensitive-code-encrypted.jar";

            encryptJarFile(jarFilePath, encryptedJarFilePath, aesKey);
            System.out.println("Encryption completed. Encrypted file is at: " + encryptedJarFilePath);           
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
