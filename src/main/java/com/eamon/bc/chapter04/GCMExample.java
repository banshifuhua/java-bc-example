package com.eamon.bc.chapter04;

import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.SecretKey;

/**
 * @author: eamon
 * @date: 2019-01-30 15:45
 * @description: A simple GCM example without Additional Associated Data (AAD)
 */
public class GCMExample {
    public static void main(String[] args) throws Exception {
        SecretKey constantKey = Utils.createConstantKey();
        byte[] iv = Hex.decode("bbaa99887766554433221100");
        byte[] msg = Strings.toByteArray("hello, world!");
        System.out.println("msg : " + Hex.toHexString(msg));
        byte[] cText = Utils.gcmEncrypt(constantKey, iv, 128, msg);
        System.out.println("cText: " + Hex.toHexString(cText));

        byte[] pText = Utils.gcmDecrypt(constantKey, iv, 128, cText);
        System.out.println("pText: " + Hex.toHexString(pText));
    }
}
