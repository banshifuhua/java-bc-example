package com.eamon.bc.chapter07;

import org.bouncycastle.jcajce.spec.KTSParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.OAEPParameterSpec;
import java.security.*;

/**
 * @author: eamon
 * @date: 2019-01-31 15:07
 * @description:
 */
public class Utils {

    /**
     * Generate a wrapped key using the RSA OAEP algorithm,
     * returning the resulting encryption.
     *
     * @param rsaPublic the public key to base the wrapping on.
     * @param secretKey the secret key to be encrypted/wrapped.
     * @return true if the signature verifies, false otherwise.
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     */
    public static byte[] keyWrapOAEP(PublicKey rsaPublic, SecretKey secretKey) throws NoSuchPaddingException,
            NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("RSA/NONE/OAEPwithSHA256andMGF1Padding", new BouncyCastleProvider());
        cipher.init(Cipher.WRAP_MODE, rsaPublic);
        return cipher.wrap(secretKey);
    }

    /**
     * Return the secret key that was encrypted in wrappedKey.
     *
     * @param rsaPrivate   the private key to use for the unwrap.
     * @param wrappedKey   the encrypted secret key.
     * @param keyAlgorithm the algorithm that the encrypted key is for.
     * @return the unwrapped SecretKey.
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    public static SecretKey keyUnwrapOAEP(PrivateKey rsaPrivate, byte[] wrappedKey, String keyAlgorithm)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance("RSA/NONE/OAEPwithSHA256andMGF1Padding", new BouncyCastleProvider());
        cipher.init(Cipher.UNWRAP_MODE, rsaPrivate);
        return (SecretKey) cipher.unwrap(wrappedKey, keyAlgorithm, Cipher.SECRET_KEY);
    }

    /**
     * Generate a wrapped key using the RSA OAEP algorithm according
     * to the passed in OAEPParameterSpec and return the resulting encryption. *
     *
     * @param rsaPublic the public key to base the wrapping on.
     * @param oaepSpec  the parameter specification for the OAEP operation.
     * @param secretKey the secret key to be encrypted/wrapped.
     * @return true if the signature verifies, false otherwise.
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     */
    public static byte[] keyWrapOAEP(PublicKey rsaPublic, OAEPParameterSpec oaepSpec, SecretKey secretKey) throws
            NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("RSA", new BouncyCastleProvider());
        cipher.init(Cipher.WRAP_MODE, rsaPublic, oaepSpec);
        return cipher.wrap(secretKey);
    }

    /**
     * Return the secret key that was encrypted in wrappedKey.
     *
     * @param rsaPrivate   the private key to use for the unwrap.
     * @param oaepSpec     the parameter specification for the OAEP operation.
     * @param wrappedKey   the encrypted secret key.
     * @param keyAlgorithm the algorithm that the encrypted key is for.
     * @return the unwrapped SecretKey.
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws InvalidAlgorithmParameterException
     */
    public static SecretKey keyUnwrapOAEP(PrivateKey rsaPrivate, OAEPParameterSpec oaepSpec, byte[] wrappedKey,
                                          String keyAlgorithm) throws NoSuchPaddingException,
            NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException {
        Cipher cipher = Cipher.getInstance("RSA", new BouncyCastleProvider());
        cipher.init(Cipher.UNWRAP_MODE, rsaPrivate, oaepSpec);
        return (SecretKey) cipher.unwrap(wrappedKey, keyAlgorithm, Cipher.SECRET_KEY);
    }

    /**
     * Generate a wrapped key using the RSA-KTS-KEM-KWS algorithm,
     * returning the resulting encryption.
     *
     * @param rsaPublic the public key to base the wrapping on.
     * @param ktsSpec   key transport parameters.
     * @param secretKey the secret key to be encrypted/wrapped.
     * @return true if the signature verifies, false otherwise.
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     */
    public static byte[] keyWrapKEMS(PublicKey rsaPublic, KTSParameterSpec ktsSpec, SecretKey secretKey)
            throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("RSA-KTS-KEM-KWS", "BCFIPS");
        cipher.init(Cipher.WRAP_MODE, rsaPublic, ktsSpec);
        return cipher.wrap(secretKey);
    }

    /**
     * Return the secret key that is encrypted in wrappedKey.
     *
     * @param rsaPrivate   the private key to use for the unwrap.
     * @param ktsSpec      key transport parameters.
     * @param wrappedKey   the encrypted secret key.
     * @param keyAlgorithm the algorithm that the encrypted key is for.
     * @return the unwrapped SecretKey.
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     */
    public static SecretKey keyUnwrapKEMS(PrivateKey rsaPrivate, KTSParameterSpec ktsSpec,
                                          byte[] wrappedKey, String keyAlgorithm) throws NoSuchPaddingException,
            NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance("RSA-KTS-KEM-KWS", "BCFIPS");
        cipher.init(Cipher.UNWRAP_MODE, rsaPrivate, ktsSpec);
        return (SecretKey) cipher.unwrap(wrappedKey, keyAlgorithm, Cipher.SECRET_KEY);
    }
}
