package com.eamon.bc.chapter06;

import org.bouncycastle.util.Strings;

import java.security.*;

/**
 * @author: eamon
 * @date: 2019-01-31 13:44
 * @description: An example of using GOST 3410-2012 to sign data and then verifying the resulting signature.
 */
public class GostR3410_2012Example {
    public static void main(String[] args) {
        try {
            KeyPair keyPair = Utils.generateGOST3410_2012KeyPair("Tc26-Gost-3410-12-512-paramSetA");
            byte[] signature = Utils.generateGOST3410_2012Signature(keyPair.getPrivate(),
                    Strings.toByteArray("Hello,World!"),
                    "ECGOST3410-2012-512");

            System.err.println("ECGOST3410-2012-512 verified: " + Utils.verifyGOST3410_2012Signature(keyPair.getPublic(),
                    Strings.toByteArray("Hello,World!"), "ECGOST3410-2012-512", signature));

        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
    }
}
