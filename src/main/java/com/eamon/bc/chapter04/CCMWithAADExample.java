package com.eamon.bc.chapter04;

import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import static com.eamon.bc.chapter04.Utils.*;

/**
 * @author: eamon
 * @date: 2019-01-30 17:16
 * @description: A simple CCM Example with Additional Associated Data (AAD)
 */
public class CCMWithAADExample {

    public static void main(String[] args) throws BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException, NoSuchProviderException, NoSuchPaddingException, InvalidAlgorithmParameterException {
        SecretKey aesKey = createConstantKey();
        byte[] iv = Hex.decode("bbaa99887766554433221100");
        byte[] msg = Strings.toByteArray("hello, world!");
        byte[] aad = Strings.toByteArray("now is the time!");
        System.out.println("msg : " + Hex.toHexString(msg));
        byte[] cText = ccmEncryptWithAAD(aesKey, iv, msg, aad);
        System.out.println("cText: " + Hex.toHexString(cText));
        byte[] pText = ccmDecryptWithAAD(aesKey, iv, cText, aad);
        System.out.println("pText: " + Hex.toHexString(pText));
    }
}
