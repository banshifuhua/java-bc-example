package com.eamon.bc.chapter04;

import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.SecretKey;

import static com.eamon.bc.chapter04.Utils.*;

/**
 * @author: eamon
 * @date: 2019-01-30 17:06
 * @description:
 */
public class GCMWithAADExample {

    public static void main(String[] args) throws Exception {
        SecretKey aesKey = createConstantKey();
        byte[] iv = Hex.decode("bbaa99887766554433221100");
        byte[] msg = Strings.toByteArray("hello, world!");
        byte[] aad = Strings.toByteArray("now is the time!");
        System.out.println("msg : " + Hex.toHexString(msg));
        byte[] cText = gcmEncryptWithAAD(aesKey, iv, msg, aad);
        System.out.println("cText: " + Hex.toHexString(cText));
        byte[] pText = gcmDecryptWithAAD(aesKey, iv, cText, aad);
        System.out.println("pText: " + Hex.toHexString(pText));
    }
}
