package com.eamon.bc.chapter03;

import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import static com.eamon.bc.chapter03.Utils.computeMac;

/**
 * @author: eamon
 * @date: 2019-01-30 14:58
 * @description: 简单的 使用 AES  CMAC的示例
 */
public class MacExample {
    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException {
        SecretKey macKey = new SecretKeySpec(Hex.decode("dfa66747de9ae63030ca32611497c827"), "AES");
        System.out.println(Hex.toHexString(computeMac("AESCMAC", macKey,
                Strings.toByteArray("Hello World!"))));
    }
}
