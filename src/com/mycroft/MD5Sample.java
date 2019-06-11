package com.mycroft;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class MD5Sample {

    private static final String MD5 = "MD5";

    public static void main(String[] args) throws NoSuchAlgorithmException {

        final String content = "Hello MD5!";

        MessageDigest messageDigest = MessageDigest.getInstance(MD5);
        messageDigest.update(content.getBytes());
        byte[] encryptBytes = messageDigest.digest();

        StringBuilder builder = new StringBuilder();
        for (byte item : encryptBytes) {
            builder.append(Integer.toHexString((0x000000FF & item) | 0xFFFFFF00).substring(6));
        }
        System.out.println(builder.toString());
    }
}
