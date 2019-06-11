package com.mycroft;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

public class AESSample {

    private static final String AES = "AES";

    private static final String AES_SEED = "mycroft";

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        final String content = "Hello AES!";

        byte[] encryptionBytes = encrypt(content.getBytes());
        System.out.println(new String(encryptionBytes));

        String decryptionContent = decrypt(encryptionBytes);
        System.out.println(decryptionContent);
    }

    private static byte[] encrypt(byte[] content) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = generateAESCipher(Cipher.ENCRYPT_MODE);

        // 使用Cipher加密内容
        return cipher.doFinal(content);
    }

    private static String decrypt(byte[] encryptionContent) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = generateAESCipher(Cipher.DECRYPT_MODE);

        byte[] decryptionBytes = cipher.doFinal(encryptionContent);

        return new String(decryptionBytes);
    }

    private static Cipher generateAESCipher(int mode) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException {
        // 下面一系列的动作都是为了生成一个Cipher
        KeyGenerator keyGenerator = KeyGenerator.getInstance(AES);

        // keysize: must be equal to 128, 192 or 256
        keyGenerator.init(128, new SecureRandom(AES_SEED.getBytes()));

        SecretKey secretKey = keyGenerator.generateKey();
        System.out.println("----------------------------------------------------------------------------------------------------------------");
        System.out.println(Arrays.asList(secretKey.getAlgorithm(), secretKey.getEncoded(), secretKey.getFormat()));
        System.out.println("----------------------------------------------------------------------------------------------------------------");

        byte[] encodedSecretKey = secretKey.getEncoded();

        SecretKeySpec secretKeySpec = new SecretKeySpec(encodedSecretKey, AES);

        Cipher cipher = Cipher.getInstance(AES);
        cipher.init(mode, secretKeySpec);
        return cipher;
    }
}
