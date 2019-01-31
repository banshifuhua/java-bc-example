package com.eamon.bc.chapter06;

import org.bouncycastle.jcajce.spec.SM2ParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.*;
import java.security.spec.*;

/**
 * @author: eamon
 * @date: 2019-01-31 09:38
 * @description: 签名工具类
 */
public class Utils {


    /**
     * 创建公钥
     *
     * @param algorithm 公钥算法
     * @param keySpec   a key specification holding details of the public key 包含公钥详细信息的密钥规范
     * @return 公钥
     * @throws InvalidKeySpecException  无效的密钥规范
     * @throws NoSuchAlgorithmException 密钥算法无效
     */
    public static PublicKey createPublicKey(String algorithm, KeySpec keySpec) throws InvalidKeySpecException,
            NoSuchAlgorithmException {
        KeyFactory keyFact = KeyFactory.getInstance(algorithm, new BouncyCastleProvider());
        return keyFact.generatePublic(keySpec);
    }

    /**
     * 生成 私钥
     *
     * @param algorithm 私钥算法
     * @param keySpec   包含私钥详细信息的密钥规范。
     * @return 私钥
     * @throws NoSuchAlgorithmException 无效的密钥规范
     * @throws InvalidKeySpecException  密钥算法无效
     */
    public static PrivateKey createPrivateKey(String algorithm, KeySpec keySpec) throws NoSuchAlgorithmException,
            InvalidKeySpecException {
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm, new BouncyCastleProvider());
        return keyFactory.generatePrivate(keySpec);
    }

    /**
     * Return a generated set of DSA parameters suitable for creating 2048 bit keys.
     * 生成 2048位的dsa 密钥参数集
     *
     * @return
     * @throws GeneralSecurityException
     */
    public static DSAParameterSpec generateDSAParams() throws GeneralSecurityException {
        AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("DSA", "BC");
        paramGen.init(2048);
        AlgorithmParameters parameters = paramGen.generateParameters();
        return parameters.getParameterSpec(DSAParameterSpec.class);
    }

    /**
     * Generate a 2048 bit DSA key pair using provider based parameters.
     *
     * @return a DSA KeyPair
     * @throws GeneralSecurityException
     */
    public static KeyPair generateDSAKeyPair() throws GeneralSecurityException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DSA", "BC");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }

    /**
     * Generate a DSA key pair using our own specified parameters
     * 使用我们自己指定的参数生成DSA密钥对
     *
     * @param dsaSpec the DSA parameters to use for key generation
     * @return a DSA KeyPair
     * @throws NoSuchProviderException            没有此密钥提供者
     * @throws NoSuchAlgorithmException           没有此密钥算法
     * @throws InvalidAlgorithmParameterException 不合法的密钥参数
     */
    public static KeyPair generateDSAKeyPair(DSAParameterSpec dsaSpec) throws NoSuchProviderException,
            NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DSA", "BC");
        keyPairGenerator.initialize(dsaSpec);

        return keyPairGenerator.generateKeyPair();
    }

    /**
     * Return true if the passed in signature verifies against the passed in DSA public key and input.
     * 验证签名
     *
     * @param dsaPublic
     * @param input
     * @param encSignature
     * @return
     * @throws NoSuchProviderException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    public static boolean verifyDSASignature(PublicKey dsaPublic, byte[] input, byte[] encSignature) throws
            NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance("SHA256WithDSA", "BC");
        signature.initVerify(dsaPublic);
        signature.update(input);
        return signature.verify(encSignature);
    }

    /**
     * Generate a EC key pair on the passed in named curve..
     * 在传入的命名曲线上生成EC密钥对。
     *
     * @param curveName the name of the curve to generate the key pair on
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     */
    public static KeyPair generateECKeyPair(String curveName) throws NoSuchAlgorithmException,
            InvalidAlgorithmParameterException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", new BouncyCastleProvider());
        keyPairGenerator.initialize(new ECGenParameterSpec(curveName));
        return keyPairGenerator.generateKeyPair();
    }

    /**
     * Generate a EC key pair on the P-256 curve
     *
     * @return
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     */
    public static KeyPair generateECKeyPair() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException,
            NoSuchProviderException {
        return generateECKeyPair("P-256");
    }

    /**
     * Generate an encoded ECDSA signature using the passed in EC private key
     * and input data.
     * 使用传入的EC私钥和输入数据生成编码的ECDSA签名。
     *
     * @param ecPrivate
     * @param input
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    public static byte[] generateECDSASignature(PrivateKey ecPrivate, byte[] input) throws
            NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance("SHA256withECDSA", new BouncyCastleProvider());
        signature.initSign(ecPrivate);
        signature.update(input);
        return signature.sign();
    }

    /**
     * 验证 ecdsa 签名数据
     *
     * @param ecPublic
     * @param input
     * @param encSignature
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    public static boolean verifyECDSASignature(PublicKey ecPublic, byte[] input, byte[] encSignature) throws
            NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance("SHA256WithECDSA", new BouncyCastleProvider());
        signature.initVerify(ecPublic);
        signature.update(input);
        return signature.verify(encSignature);
    }

    /**
     * Generate an encoded Deterministic ECDSA (ECDDSA) signature using the passed in EC private key and input data.
     *
     * @param ecPrivate the private key for generating the signature with
     * @param input     the input to be signed.
     * @return the encoded signature.
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    public static byte[] generateECDDSASignature(PrivateKey ecPrivate, byte[] input) throws NoSuchAlgorithmException,
            InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance("SHA256withECDDSA", new BouncyCastleProvider());
        signature.initSign(ecPrivate);
        signature.update(input);
        return signature.sign();
    }

    /**
     * Generate a DSTU 4145-2002 key pair for the passed in named parameter set
     * 为传入的命名参数集生成DSTU 4145-2002密钥对
     *
     * @param curveNo the curve number to use (range [0-9])
     * @return a EC KeyPair
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     */
    public static KeyPair generateDSTU4145KeyPair(int curveNo) throws NoSuchAlgorithmException,
            InvalidAlgorithmParameterException {
        KeyPairGenerator pairGenerator = KeyPairGenerator.getInstance("DSTU4145", new BouncyCastleProvider());
        pairGenerator.initialize(new ECGenParameterSpec("1.2.804.2.1.1.1.1.3.1.1.2." + curveNo));
        return pairGenerator.generateKeyPair();
    }

    /**
     * Generate an encoded DSTU 4145 signature based on the SM3 digest using the
     * passed in EC private key and input data.
     * <p>
     * 使用传入的EC私钥和输入数据，基于SM3摘要生成编码的DSTU 4145签名。
     *
     * @param ecPrivate ecPrivate the private key for generating the signature with
     * @param input     the input to be signed.
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    public static byte[] generateDSTU4145Signature(PrivateKey ecPrivate, byte[] input) throws NoSuchAlgorithmException,
            InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance("DSTU4145", new BouncyCastleProvider());
        signature.initSign(ecPrivate);
        signature.update(input);
        return signature.sign();
    }

    /**
     * Return true if the passed in DSTU 4145 signature verifies against the passed in EC public key and input.
     * 如果传入的DSTU 4145签名验证传入的EC公钥和输入，则返回true
     *
     * @param ecPublic     the public key of the signature creator
     * @param input        the input that was supposed to have been signed
     * @param encSignature the encoded signature.
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    public static boolean verifyDSTU4145Signature(PublicKey ecPublic, byte[] input, byte[] encSignature) throws
            NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance("DSTU4145", new BouncyCastleProvider());
        signature.initVerify(ecPublic);
        signature.update(input);
        return signature.verify(encSignature);
    }

    /**
     * Generate a GOST 3410-2012 key pair for the passed in named parameter set
     * 为传入的命名参数集生成GOST 3410-2012密钥对
     *
     * @param paramSetName the name of the parameter set to base the key pair on.
     * @return a EC KeyPair
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     */
    public static KeyPair generateGOST3410_2012KeyPair(String paramSetName) throws NoSuchAlgorithmException,
            InvalidAlgorithmParameterException {
        KeyPairGenerator keyPair = KeyPairGenerator.getInstance("ECGOST3410-2012", new BouncyCastleProvider());
        keyPair.initialize(new ECGenParameterSpec(paramSetName));
        return keyPair.generateKeyPair();
    }

    /**
     * Generate an encoded GOST 3410-2012 signature using the passed in GOST 3410-2012 private key and input data
     *
     * @param ecPrivate the private key for generating the signature with
     * @param input     the input to be signed.
     * @param sigName   the name of the signature algorithm to use
     * @return the encoded signature
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    public static byte[] generateGOST3410_2012Signature(PrivateKey ecPrivate, byte[] input, String sigName)
            throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance(sigName, new BouncyCastleProvider());
        signature.initSign(ecPrivate);
        signature.update(input);
        return signature.sign();
    }

    /**
     * Return true if the passed in GOST 3410-2012 signature verifies against the passed in
     * GOST 3410-2012 public key and input.
     *
     * @param ecPublic     the public key of the signature creator
     * @param input        the input that was supposed to have been signed.
     * @param signName     the name of the signature algorithm to use.
     * @param encSignature the encoded signature.
     * @return true if the signature verifies, false otherwise
     */
    public static boolean verifyGOST3410_2012Signature(PublicKey ecPublic, byte[] input, String signName,
                                                       byte[] encSignature) throws NoSuchAlgorithmException,
            InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance(signName, new BouncyCastleProvider());
        signature.initVerify(ecPublic);
        signature.update(input);
        return signature.verify(encSignature);
    }

    /**
     * Generate a 2048 bit RSA key pair using user specified parameters.
     * 生成 rsa密钥对
     *
     * @return a RSA KeyPair
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     */
    public static KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator pairGenerator = KeyPairGenerator.getInstance("RSA", new BouncyCastleProvider());
        pairGenerator.initialize(new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4));
        return pairGenerator.generateKeyPair();
    }

    /**
     * Generate an encoded RSA signature using the passed in private key and input data.
     *
     * @param rsaPrivate the private key for generating the signature with
     * @param input      the input to be signed.
     * @return the encoded signature.
     * @throws NoSuchAlgorithmException
     * @throws SignatureException
     * @throws InvalidKeyException
     */
    public static byte[] generatePKCS1dot5Signature(PrivateKey rsaPrivate, byte[] input) throws
            NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        Signature signature = Signature.getInstance("SHA256withRSA", new BouncyCastleProvider());
        signature.initSign(rsaPrivate);
        signature.update(input);
        return signature.sign();
    }

    /**
     * Return true if the passed in signature verifies against the passed in RSA public key and input.
     *
     * @param rsaPublic    the public key of the signature creator
     * @param input        the input that was supposed to have been signed.
     * @param encSignature the encoded signature.
     * @return true if the signature verifies, false otherwise
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    public static boolean verifyPKCS1dot5Signature(PublicKey rsaPublic, byte[] input, byte[] encSignature)
            throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance("SHA256withRSA", new BouncyCastleProvider());
        signature.initVerify(rsaPublic);
        signature.update(input);
        return signature.verify(encSignature);
    }

    /**
     * Generate an encoded RSA signature using the passed in private key and input data.
     *
     * @param rsaPrivate the private key for generating the signature with
     * @param input      the input to be signed.
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    public static byte[] generateRSAPSSSignature(PrivateKey rsaPrivate, byte[] input)
            throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance("SHA256withRSAandMGF1", new BouncyCastleProvider());
        signature.initSign(rsaPrivate);
        signature.update(input);
        return signature.sign();
    }

    /**
     * Return true if the passed in signature verifies against the passed in RSA public key and input
     *
     * @param rsaPublic    the public key of the signature creator
     * @param input        the input that was supposed to have been signed
     * @param encSignature the encoded signature.
     * @return true if the signature verifies, false otherwise.
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    public static boolean verifyRSAPSSSignature(PublicKey rsaPublic, byte[] input, byte[] encSignature)
            throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance("SHA256withRSAandMGF1", new BouncyCastleProvider());
        signature.initVerify(rsaPublic);
        signature.update(input);
        return signature.verify(encSignature);
    }

    /**
     * Generate an encoded RSA signature using the passed in private key and input data.
     *
     * @param rsaPrivate the private key for generating the signature with
     * @param pssSpec
     * @param input      the input to be signed.
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    public static byte[] generateRSAPSSSignature(PrivateKey rsaPrivate, PSSParameterSpec pssSpec, byte[] input)
            throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException,
            SignatureException {
        Signature signature = Signature.getInstance("RSAPSS", new BouncyCastleProvider());
        signature.setParameter(pssSpec);
        signature.initSign(rsaPrivate);
        signature.update(input);
        return signature.sign();
    }

    /**
     * Return true if the passed in signature verifies against the passed in RSA public key and input.
     *
     * @param rsaPublic        the public key of the signature creator
     * @param pssParameterSpec
     * @param input            the input that was supposed to have been signed
     * @param encSignature     the encoded signature
     * @return true if the signature verifies, false otherwise
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    public static boolean verifyRSAPSSSignature(PublicKey rsaPublic, PSSParameterSpec pssParameterSpec,
                                                byte[] input, byte[] encSignature) throws NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance("RSAPSS", new BouncyCastleProvider());
        signature.setParameter(pssParameterSpec);
        signature.initVerify(rsaPublic);
        signature.update(input);
        return signature.verify(encSignature);
    }

    /**
     * Generate an encoded SM2 signature based on the SM3 digest using the passed in EC private key and input data.
     *
     * @param ecPrivate the private key for generating the signature with
     * @param input     the input to be signed
     * @return the encoded signature.
     */
    public static byte[] generateSM2Signature(PrivateKey ecPrivate, byte[] input) throws NoSuchAlgorithmException,
            InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance("SM3withSM2", new BouncyCastleProvider());
        signature.initSign(ecPrivate);
        signature.update(input);
        return signature.sign();
    }

    /**
     * Return true if the passed in SM3withSM2 signature verifies against the passed in EC public key and input.
     *
     * @param ecPublic     the public key of the signature creator
     * @param input        the input that was supposed to have been signed.
     * @param encSignature the encoded signature.
     * @return true if the signature verifies, false otherwise
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    public static boolean verifySM2Signature(PublicKey ecPublic, byte[] input, byte[] encSignature)
            throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance("SM3withSM2", new BouncyCastleProvider());
        signature.initVerify(ecPublic);
        signature.update(input);
        return signature.verify(encSignature);
    }

    /**
     * Generate an encoded SM2 signature based on the SM3 digest using the
     * passed in EC private key and input data.
     *
     * @param ecPrivate the private key for generating the signature with.
     * @param sm2Spec   the SM2 specification carrying the ID of the signer.
     * @param input     the input to be signed.
     * @return the encoded signature.
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    public static byte[] generateSM2Signature(PrivateKey ecPrivate, SM2ParameterSpec sm2Spec, byte[] input)
            throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance("SM3withSM2", new BouncyCastleProvider());
        signature.setParameter(sm2Spec);
        signature.initSign(ecPrivate);
        signature.update(input);
        return signature.sign();
    }

    /**
     * Return true if the passed in SM3withSM2 signature verifies against
     * the passed in EC public key and input.
     *
     * @param ecPublic     the public key of the signature creator.
     * @param sm2Spec      the SM2 specification carrying the expected ID of the signer.
     * @param input        the input that was supposed to have been signed.
     * @param encSignature the encoded signature.
     * @return true if the signature verifies, false otherwise.
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    public static boolean verifySM2Signature(PublicKey ecPublic, SM2ParameterSpec sm2Spec,
                                             byte[] input, byte[] encSignature) throws NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance("SM3withSM2", new BouncyCastleProvider());
        signature.setParameter(sm2Spec);
        signature.initVerify(ecPublic);
        signature.update(input);
        return signature.verify(encSignature);
    }


}
