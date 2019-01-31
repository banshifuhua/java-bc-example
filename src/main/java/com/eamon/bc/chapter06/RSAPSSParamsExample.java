package com.eamon.bc.chapter06;

import org.bouncycastle.util.Strings;

import java.security.*;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

/**
 * @author: eamon
 * @date: 2019-01-31 14:22
 * @description: An example of using RSA PSS with a PSSParameterSpec based on SHA-256.
 */
public class RSAPSSParamsExample {
    public static void main(String[] args) {
        try {
            KeyPair keyPair = Utils.generateRSAKeyPair();
            PSSParameterSpec parameterSpec = new PSSParameterSpec("SHA-256", "MGF1",
                    new MGF1ParameterSpec("SHA-256"), 32, 1);

            byte[] encSignature = Utils.generateRSAPSSSignature(keyPair.getPrivate(), parameterSpec,
                    Strings.toByteArray("Hello,World!"));

            System.err.println("RSA PSS verified: " + Utils.verifyRSAPSSSignature(keyPair.getPublic(), parameterSpec,
                    Strings.toByteArray("Hello,World!"), encSignature));

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
