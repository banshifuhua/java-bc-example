package com.eamon.bc.chapter02;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * @author: eamon
 * @date: 2019-01-30 13:55
 * @description:
 */
public class CBCPadExample {
    public static void main(String[] args) {
        try {
            byte[] keyBytes = Hex.decode("000102030405060708090a0b0c0d0e0f");
            SecretKeySpec spec = new SecretKeySpec(keyBytes, "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", new BouncyCastleProvider());

            byte[] input = Hex.decode("a0a1a2a3a4a5a6a7a0a1a2a3a4a5a6a7a0a1a2a3a4a5a6a7a0");
            System.out.println("input : " + Hex.toHexString(input));

            byte[] iv = Hex.decode("9f741fdb5d8845bdb48a94394e84f8a3");
            cipher.init(Cipher.ENCRYPT_MODE, spec, new IvParameterSpec(iv));
            byte[] output = cipher.doFinal(input);
            System.out.println("encrypted: " + Hex.toHexString(output));

            cipher.init(Cipher.DECRYPT_MODE, spec, new IvParameterSpec(iv));
            byte[] finalOutput = new byte[cipher.getOutputSize(output.length)];
            int len = cipher.update(output, 0, output.length, finalOutput, 0);
            len += cipher.doFinal(finalOutput, len);
            System.out.println("decrypted: " + Hex.toHexString(Arrays.copyOfRange(finalOutput, 0, len)));

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (ShortBufferException e) {
            e.printStackTrace();
        }

    }
}
