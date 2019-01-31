package com.eamon.bc.chapter06;

import org.bouncycastle.util.Strings;

import java.security.*;

/**
 * @author: eamon
 * @date: 2019-01-31 13:28
 * @description: An example of using DSTU 4145-2002 to sign data and then verifying the resulting signature.
 * 使用DSTU 4145-2002对数据进行签名然后验证生成的签名的示例。
 */
public class DSTU4145Example {
    public static void main(String[] args) {
        try {
            KeyPair keyPair = Utils.generateDSTU4145KeyPair(0);

            byte[] dstuSig = Utils.generateDSTU4145Signature(keyPair.getPrivate(),
                    Strings.toByteArray("Hello World!"));

            System.err.println("DSTU 4145-2002 verified: " + Utils.verifyDSTU4145Signature(keyPair.getPublic(),
                    Strings.toByteArray("Hello World!"), dstuSig));

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        }
    }
}
