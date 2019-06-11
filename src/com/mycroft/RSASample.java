package com.mycroft;

import javafx.util.Pair;
import sun.security.rsa.RSAKeyPairGenerator;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class RSASample {

    private static final String RSA = "RSA";
    private static final String RSA_SEED = "mycroft";

    public static void main(String[] args) throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException {
        final String content = "Hello RSA!";

        Pair<PrivateKey, PublicKey> keyPair = generateRSAKey();

        String privateKeyString = new String(Base64.getEncoder().encode(keyPair.getKey().getEncoded()));
        String publicKeyString = new String(Base64.getEncoder().encode(keyPair.getValue().getEncoded()));

        System.out.println(privateKeyString);
        System.out.println(publicKeyString);

//        byte[] encryptContent = encrypt(content, keyPair.getValue());
        // 这里使用 private key string 反过来获得 PublicKey
        byte[] encryptContent = encrypt(content, transferString2PublicKey(publicKeyString));

        System.out.println(new String(encryptContent));

//        byte[] decryptContent = decrypt(encryptContent, keyPair.getKey());
        // 使用 public key string 反过来获得 PrivateKey
        byte[] decryptContent = decrypt(encryptContent, transferString2PrivateKey(privateKeyString));
        System.out.println(new String(decryptContent));
    }

    private static PrivateKey transferString2PrivateKey(String privateKeyString) throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyString);
        KeyFactory keyFactory = KeyFactory.getInstance(RSA);
        return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));
    }

    private static PublicKey transferString2PublicKey(String publicKeyString) throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyString);
        KeyFactory keyFactory = KeyFactory.getInstance(RSA);
        return keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyBytes));
    }

    /**
     * 加密
     *
     * @param content   加密的内容
     * @param publicKey 公钥
     * @return
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    private static byte[] encrypt(String content, PublicKey publicKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(RSA);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(content.getBytes());
    }

    /**
     * 解密
     *
     * @param encryptContent 解密的内容
     * @param privateKey     私钥
     * @return
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    private static byte[] decrypt(byte[] encryptContent, PrivateKey privateKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(RSA);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(encryptContent);
    }

    /**
     * 生成RSA秘钥对
     *
     * @return pair of private key and public key
     */
    private static Pair<PrivateKey, PublicKey> generateRSAKey() {
        RSAKeyPairGenerator keyPairGenerator = new RSAKeyPairGenerator();
        keyPairGenerator.initialize(512, new SecureRandom(RSA_SEED.getBytes()));
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        return new Pair<>(privateKey, publicKey);
    }
}
