package com.eamon.bc.chapter02;

import org.bouncycastle.jcajce.io.CipherInputStream;
import org.bouncycastle.jcajce.io.CipherOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.Streams;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.AlgorithmParameters;

/**
 * @author: eamon
 * @date: 2019-01-30 14:26
 * @description:
 */
public class CipherIOExample {

    public static void main(String[] args) throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES", new BouncyCastleProvider());
        SecretKey key = keyGenerator.generateKey();
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", new BouncyCastleProvider());
        byte[] input = Hex.decode("a0a1a2a3a4a5a6a7a0a1a2a3a4a5a6a7a0a1a2a3a4a5a6a7a0");
        System.out.println("input : " + Hex.toHexString(input));
        cipher.init(Cipher.ENCRYPT_MODE, key);
        AlgorithmParameters ivParams = cipher.getParameters();
        // encrypt the plain text
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        CipherOutputStream cOut = new CipherOutputStream(bOut, cipher);
        cOut.write(input);
        cOut.close();
        byte[] output = bOut.toByteArray();
        System.out.println("encrypted: " + Hex.toHexString(output));
        cipher.init(Cipher.DECRYPT_MODE, key, ivParams);
        // decrypt the cipher text
        ByteArrayInputStream bIn = new ByteArrayInputStream(output);
        CipherInputStream cIn = new CipherInputStream(bIn, cipher);
        byte[] decrypted = Streams.readAll(cIn);
        System.out.println("decrypted: " + Hex.toHexString(decrypted));

    }
}
