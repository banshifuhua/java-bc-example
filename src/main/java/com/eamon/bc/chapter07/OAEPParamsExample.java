package com.eamon.bc.chapter07;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.spec.MGF1ParameterSpec;

import static com.eamon.bc.chapter06.Utils.generateRSAKeyPair;
import static com.eamon.bc.chapter07.Utils.keyUnwrapOAEP;
import static com.eamon.bc.chapter07.Utils.keyWrapOAEP;

/**
 * @author: eamon
 * @date: 2019-01-31 15:42
 * @description:
 */
public class OAEPParamsExample {
    public static void main(String[] args) {
        try {
            SecretKey aesKey = new SecretKeySpec(Hex.decode("000102030405060708090a0b0c0d0e0f"), "AES");
            KeyPair kp = generateRSAKeyPair();
            OAEPParameterSpec oaepSpec = new OAEPParameterSpec("SHA-256",
                    "MGF1", MGF1ParameterSpec.SHA256, new PSource.PSpecified(Strings.toByteArray("My Label")));
            byte[] wrappedKey = keyWrapOAEP(kp.getPublic(), aesKey);
            SecretKey recoveredKey = keyUnwrapOAEP(kp.getPrivate(), oaepSpec, wrappedKey, aesKey.getAlgorithm());
            System.out.println(Arrays.areEqual(aesKey.getEncoded(), recoveredKey.getEncoded()));

        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
    }
}
