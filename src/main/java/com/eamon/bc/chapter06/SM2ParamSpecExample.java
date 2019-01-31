package com.eamon.bc.chapter06;

import org.bouncycastle.jcajce.spec.SM2ParameterSpec;
import org.bouncycastle.util.Strings;

import java.security.*;

/**
 * @author: eamon
 * @date: 2019-01-31 14:52
 * @description: An example of using SM2 with an SM2ParameterSpec to specify the ID string for the signature.
 */
public class SM2ParamSpecExample {
    public static void main(String[] args) {
       try {
           KeyPair ecKeyPair = Utils.generateECKeyPair("sm2p256v1");
           SM2ParameterSpec spec = new SM2ParameterSpec(Strings.toByteArray("Signer@Octets.ID"));
           byte[] encSignature = Utils.generateSM2Signature(ecKeyPair.getPrivate(), spec,
                   Strings.toByteArray("Hello,World!"));
           System.err.println("SM2 verified: " + Utils.verifySM2Signature(ecKeyPair.getPublic(), spec,
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
