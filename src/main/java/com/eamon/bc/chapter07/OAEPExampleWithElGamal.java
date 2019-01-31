package com.eamon.bc.chapter07;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;

/**
 * @author: eamon
 * @date: 2019-01-31 15:53
 * @description: Simple example showing secret key wrapping and unwrapping based on ElGamal OAEP.
 */
public class OAEPExampleWithElGamal {

    public static KeyPair generateDHKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPair = KeyPairGenerator.getInstance("DH", new BouncyCastleProvider());
        keyPair.initialize(2048);
        return keyPair.generateKeyPair();
    }

    public static byte[] keyWrapOAEP(PublicKey dhPublic, SecretKey secretKey) throws NoSuchPaddingException,
            NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("ElGamal/NONE/OAEPwithSHA256andMGF1Padding", new BouncyCastleProvider());
        cipher.init(Cipher.WRAP_MODE, dhPublic);
        return cipher.wrap(secretKey);
    }

    public static SecretKey keyUnwrapOAEP(PrivateKey dhPrivate, byte[] wrappedKey, String keyAlgorithm)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance("ElGamal/NONE/OAEPwithSHA256andMGF1Padding", new BouncyCastleProvider());
        cipher.init(Cipher.UNWRAP_MODE, dhPrivate);
        return (SecretKey) cipher.unwrap(wrappedKey, keyAlgorithm, Cipher.SECRET_KEY);
    }

    public static void main(String[] args) {
     try {
         SecretKey aesKey = new SecretKeySpec(Hex.decode("000102030405060708090a0b0c0d0e0f"), "AES");
         KeyPair kp = generateDHKeyPair();
         byte[] wrappedKey = keyWrapOAEP(kp.getPublic(), aesKey);
         SecretKey recoveredKey = keyUnwrapOAEP(kp.getPrivate(),
                 wrappedKey, aesKey.getAlgorithm());
         System.out.println(Arrays.areEqual(aesKey.getEncoded(), recoveredKey.getEncoded()));

     } catch (NoSuchPaddingException e) {
         e.printStackTrace();
     } catch (NoSuchAlgorithmException e) {
         e.printStackTrace();
     } catch (IllegalBlockSizeException e) {
         e.printStackTrace();
     } catch (InvalidKeyException e) {
         e.printStackTrace();
     }
    }
}
