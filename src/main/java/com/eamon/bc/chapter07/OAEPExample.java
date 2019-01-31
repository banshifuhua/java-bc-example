package com.eamon.bc.chapter07;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

import static com.eamon.bc.chapter06.Utils.generateRSAKeyPair;
import static com.eamon.bc.chapter07.Utils.keyUnwrapOAEP;
import static com.eamon.bc.chapter07.Utils.keyWrapOAEP;

/**
 * @author: eamon
 * @date: 2019-01-31 15:24
 * @description: Simple example showing secret key wrapping and unwrapping based on OAEP
 */
public class OAEPExample {
    public static void main(String[] args) {
       try {
           SecretKey aesKey = new SecretKeySpec(Hex.decode("dfa66747de9ae63030ca32611497c827"), "AES");
           KeyPair keyPair = generateRSAKeyPair();
           byte[] wrappedKey = keyWrapOAEP(keyPair.getPublic(), aesKey);
           SecretKey recoveredKey = keyUnwrapOAEP(keyPair.getPrivate(), wrappedKey, aesKey.getAlgorithm());
           System.out.println(Arrays.areEqual(aesKey.getEncoded(), recoveredKey.getEncoded()));
       } catch (NoSuchAlgorithmException e) {
           e.printStackTrace();
       } catch (InvalidKeyException e) {
           e.printStackTrace();
       } catch (InvalidAlgorithmParameterException e) {
           e.printStackTrace();
       } catch (NoSuchPaddingException e) {
           e.printStackTrace();
       } catch (IllegalBlockSizeException e) {
           e.printStackTrace();
       }

    }
}
