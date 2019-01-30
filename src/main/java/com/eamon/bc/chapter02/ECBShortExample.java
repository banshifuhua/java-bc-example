package com.eamon.bc.chapter02;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

/**
 * @author: eamon
 * @date: 2019-01-30 11:18
 * @description: Electronic Code Book mode
 */
public class ECBShortExample {
    public static void main(String[] args) {
        try {
            byte[] keyBytes = Hex.decode("000102030405060708090a0b0c0d0e0f");
            SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
            Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding", "BC");
            byte[] input = Hex.decode("a0a1a2a3a4a5a6a7a0a1a2a3a4a5a6a7");
            System.out.println("input: " + Hex.toHexString(input));

            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] output = cipher.doFinal(input);
            System.out.println("encrypted: " + Hex.toHexString(output));

            cipher.init(Cipher.DECRYPT_MODE, key);
            byte[] decrypt = cipher.doFinal(output);
            System.out.println("decrypted: " + Hex.toHexString(decrypt));

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }
    }
}
