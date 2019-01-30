package com.eamon.bc.chapter04;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;

/**
 * @author: eamon
 * @date: 2019-01-30 16:33
 * @description: A simple GCM example that shows data corruption.
 */
public class GCMWithParamGenExample {

    public static void main(String[] args) throws Exception {
        SecretKey key = Utils.createConstantKey();
        AlgorithmParameterGenerator generator = AlgorithmParameterGenerator.getInstance("GCM", new BouncyCastleProvider());
        byte[] msg = Strings.toByteArray("hello, world!");
        System.out.println("msg : " + Hex.toHexString(msg));
        AlgorithmParameters algorithmParameters = generator.generateParameters();
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", new BouncyCastleProvider());
        cipher.init(Cipher.ENCRYPT_MODE, key, algorithmParameters);
        byte[] cText = cipher.doFinal(msg);
        System.out.println("cText: " + Hex.toHexString(cText));
        GCMParameterSpec gcmParameterSpec = algorithmParameters.getParameterSpec(GCMParameterSpec.class);
        byte[] pText = Utils.gcmDecrypt(key, gcmParameterSpec.getIV(), gcmParameterSpec.getTLen(), cText);
        System.out.println("pText: " + Hex.toHexString(pText));
    }
}
