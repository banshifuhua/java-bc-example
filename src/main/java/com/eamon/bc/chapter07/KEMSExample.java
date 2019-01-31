package com.eamon.bc.chapter07;

import org.bouncycastle.jcajce.spec.KTSParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;

import static com.eamon.bc.chapter07.Utils.keyUnwrapKEMS;
import static com.eamon.bc.chapter07.Utils.keyWrapKEMS;

/**
 * @author: eamon
 * @date: 2019-01-31 16:06
 * @description:
 */
public class KEMSExample {
    public static void main(String[] args) {
        try {
            Security.addProvider(new BouncyCastleProvider());
            SecretKey aesKey = new SecretKeySpec(Hex.decode("000102030405060708090a0b0c0d0e0f"), "AES");
            KeyPairGenerator keyPair = KeyPairGenerator.getInstance("RSA", "BCFIPS");
            keyPair.initialize(2048);
            KeyPair kp = keyPair.generateKeyPair();
            KTSParameterSpec ktsSpec =new KTSParameterSpec.Builder("AESKWP", 256,
                    Strings.toByteArray("OtherInfo Data")).build();
            byte[] wrappedKey = keyWrapKEMS(kp.getPublic(), ktsSpec, aesKey);
            SecretKey recoveredKey = keyUnwrapKEMS(kp.getPrivate(), ktsSpec, wrappedKey, aesKey.getAlgorithm());
            System.out.println(Arrays.areEqual(aesKey.getEncoded(), recoveredKey.getEncoded()));

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }
    }
}
