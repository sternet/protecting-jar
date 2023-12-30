package com.shternconsulting.smartbox;

import java.io.File;
import java.io.FileOutputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.json.JSONObject;

public class UseTerminalService {

	public static PrivateKey getPrivateKeyFromFile(String privateKeyPath) throws Exception {
	    byte[] keyBytes = Files.readAllBytes(Paths.get(privateKeyPath));
	    PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(keyBytes));
	    KeyFactory kf = KeyFactory.getInstance("RSA");
	    return kf.generatePrivate(spec);
	}
	
	public static String decryptRSA(String encryptedData, PrivateKey privateKey) throws Exception {
	    Cipher cipher = Cipher.getInstance("RSA");
	    cipher.init(Cipher.DECRYPT_MODE, privateKey);
	    byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedData));
	    return new String(decryptedBytes);
	}
	
	public static String readLicenseHash(String licenseFilePath, String privateKeyPath) {
		try {
			String jsonData = new String(Files.readAllBytes(Paths.get(licenseFilePath)));
	        JSONObject jsonObject = new JSONObject(jsonData);
	        String encryptedHash = jsonObject.getString("ehash");
	        
	        PrivateKey privateKey = getPrivateKeyFromFile(privateKeyPath);
	        String decryptedHash = decryptRSA(encryptedHash, privateKey);

	        return decryptedHash;
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
    }
	
	public static byte[] decryptAES(byte[] data, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(data);
    }

	@SuppressWarnings("unused")
	private static void LoadAndUseJar(String jarToUsePath) {
		try { 
	        URLClassLoader classLoader = URLClassLoader.newInstance(new URL[] { new URL("file:" + jarToUsePath) });
	        Class<?> terminalServiceClass = Class.forName("com.shternconsulting.smartbox.sensitive.TerminalService", true, classLoader);
	        Constructor<?> constructor = terminalServiceClass.getConstructor(String.class);
	        Object terminalServiceInstance = constructor.newInstance("Shtern Consulting");
	        Method doOperationMethod = terminalServiceClass.getMethod("DoOperation", String.class, String.class);
	        Object result = doOperationMethod.invoke(terminalServiceInstance, "talk", "me");
	        System.out.println(String.format("Service result: %d", result));
		} catch(Exception e) {
			e.printStackTrace();
		}
	}

	private static byte[] hkdf(byte[] input, int length) {
        HKDFBytesGenerator hkdf = new HKDFBytesGenerator(new SHA256Digest());
        hkdf.init(new HKDFParameters(input, null, null));
        byte[] okm = new byte[length];
        hkdf.generateBytes(okm, 0, length);
        return okm;
    }
	
	public static SecretKey createAESKey(String keyMaterial) {
		byte[] decodedKey = Base64.getDecoder().decode(keyMaterial);
        byte[] aesKeyMaterial = hkdf(decodedKey, 32);
        return new SecretKeySpec(aesKeyMaterial, "AES");
    }
	
	private static String DecryptSensitiveJar(String encryptedJarFilePath, String keyMaterial) {
		try { 
            SecretKey aesKey = createAESKey(keyMaterial);
            System.out.println("Generated AES key from the key material: " + keyMaterial);
	
	        byte[] encryptedJarBytes = Files.readAllBytes(Paths.get(encryptedJarFilePath));
	        byte[] decryptedJarBytes = decryptAES(encryptedJarBytes, aesKey);
	
	        File tempJarFile = File.createTempFile("decrypted", ".jar");
	        try (FileOutputStream fos = new FileOutputStream(tempJarFile)) {
	            fos.write(decryptedJarBytes);
	        }
	        
	        return tempJarFile.getAbsolutePath();
		} catch(Exception e) {
			e.printStackTrace();
			return null;
		}
	}
	
	public static void main(String[] args) {
        try {
        	String path = "../libraries/";
        	String licenseFilePath = path + "license.json";
        	String privateKeyPath = path + "terminal-private.key";
        	String base64EncodedKey = readLicenseHash(licenseFilePath, privateKeyPath);

            String encryptedJarFilePath = path + "sensitive-code-encrypted.jar";
            String jarToUsePath = DecryptSensitiveJar(encryptedJarFilePath, base64EncodedKey);
        	
            LoadAndUseJar(jarToUsePath);
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
