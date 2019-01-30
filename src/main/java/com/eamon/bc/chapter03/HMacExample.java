package com.eamon.bc.chapter03;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

import static com.eamon.bc.chapter03.Utils.computeMac;

/**
 * @author: eamon
 * @date: 2019-01-30 15:04
 * @description: A simple example of using a HMAC SHA-256.
 */
public class HMacExample {
    public static void main(String[] args) throws InvalidKeyException, NoSuchAlgorithmException {
        Security.addProvider(new BouncyCastleProvider());
        SecretKey macKey = new SecretKeySpec(Hex.decode("2ccd85dfc8d18cb5d84fef4b19855469" +
                "9fece6e8692c9147b0da983f5b7bd413"), "HmacSHA256");
        System.out.println(Hex.toHexString(computeMac("HmacSHA256", macKey, Strings.toByteArray("Hello World!"))));
    }
}
