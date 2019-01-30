package com.eamon.bc.chapter03;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * @author: eamon
 * @date: 2019-01-30 15:04
 * @description:
 */
public class Utils {
    /**
     * Return a MAC computed over data using the passed in MAC algorithm
     * type algorithm.
     *
     * @param algorithm the name of the MAC algorithm.
     * @param key       an appropriate secret key for the MAC algorithm.
     * @param data      the input for the MAC function.
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    public static byte[] computeMac(String algorithm, SecretKey key, byte[] data)
            throws NoSuchAlgorithmException, InvalidKeyException {
        Mac mac = Mac.getInstance(algorithm, new BouncyCastleProvider());
        mac.init(key);
        mac.update(data);
        return mac.doFinal();
    }

    /**
     * Return a DigestCalculator for the passed in algorithm digestName.
     * 返回一个 指定摘要算法名称的 摘要计算器
     *
     * @param digestName 摘要名称
     * @return
     * @throws OperatorCreationException
     */
    public static DigestCalculator createDigestCalculator(String digestName) throws OperatorCreationException {
        DefaultDigestAlgorithmIdentifierFinder finder = new DefaultDigestAlgorithmIdentifierFinder();
        JcaDigestCalculatorProviderBuilder builder = new JcaDigestCalculatorProviderBuilder();
        DigestCalculatorProvider calculatorProvider = builder.setProvider(new BouncyCastleProvider()).build();
        return calculatorProvider.get(finder.find(digestName));
    }
}
