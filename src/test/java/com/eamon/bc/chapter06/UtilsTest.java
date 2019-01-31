package com.eamon.bc.chapter06;

import org.junit.Test;

import java.math.BigInteger;
import java.security.*;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.InvalidKeySpecException;

/**
 * @author: eamon
 * @date: 2019-01-31 10:43
 * @description:
 */
public class UtilsTest {

    @Test
    public void testCreatePublicKey() throws InvalidKeySpecException, NoSuchAlgorithmException {
        DSAPublicKeySpec spec = new DSAPublicKeySpec(BigInteger.valueOf(123456789), BigInteger.ONE, BigInteger.ZERO, BigInteger.TEN);
        PublicKey publicKey = Utils.createPublicKey("DSA", spec);
        System.out.println(publicKey.getAlgorithm());
    }

    @Test
    public void testEcdsa() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException, InvalidKeyException {
        KeyPair keyPair = Utils.generateECKeyPair();
        String data = "Hello World!";
        byte[] ecdsaSignature = Utils.generateECDSASignature(keyPair.getPrivate(), data.getBytes());
        boolean b = Utils.verifyECDSASignature(keyPair.getPublic(), data.getBytes(), ecdsaSignature);
        System.out.println(b);
    }

}