package com.eamon.bc.chapter02;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * @author: eamon
 * @date: 2019-01-30 13:25
 * @description: CBC 模式 加密解密
 */
public class CBCExample {

    public static void main(String[] args) {
        try {
            byte[] keyBytes = Hex.decode("000102030405060708090a0b0c0d0e0f");
            SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding", new BouncyCastleProvider());

            byte[] input = Hex.decode("a0a1a2a3a4a5a6a7a0a1a2a3a4a5a6a7" + "a0a1a2a3a4a5a6a7a0a1a2a3a4a5a6a7");
            System.out.println("input : " + Hex.toHexString(input));

            byte[] iv = Hex.decode("9f741fdb5d8845bdb48a94394e84f8a3");

            cipher.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(iv));
            byte[] output = cipher.doFinal(input);
            System.out.println("encrypted : " + Hex.toHexString(output));

            cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(iv));
            System.out.println("decrypted : " + Hex.toHexString(cipher.doFinal(output)));

        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }
    }
}
