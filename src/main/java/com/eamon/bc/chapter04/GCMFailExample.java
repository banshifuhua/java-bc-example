package com.eamon.bc.chapter04;

import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.SecretKey;

/**
 * @author: eamon
 * @date: 2019-01-30 16:28
 * @description:
 */
public class GCMFailExample {
    public static void main(String[] args) throws Exception {
        SecretKey key = Utils.createConstantKey();
        byte[] iv = Hex.decode("bbaa99887766554433221100");
        byte[] msg = Strings.toByteArray("hello, world!");
        byte[] cText = Utils.gcmEncrypt(key, iv, 128, msg);
        // tamper with the cipher text
        cText[0] = (byte) ~cText[0];
        byte[] pText = Utils.gcmDecrypt(key, iv, 128, cText);
    }
}
