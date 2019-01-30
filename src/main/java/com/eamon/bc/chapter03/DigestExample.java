package com.eamon.bc.chapter03;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * @author: eamon
 * @date: 2019-01-30 14:43
 * @description:
 */
public class DigestExample {
    public static void main(String[] args) throws NoSuchAlgorithmException {
        System.out.println(Hex.toHexString(computeDigest("SHA-256", Strings.toByteArray("Hello World!"))));
    }

    /**
     * 使用传入的算法digestName返回通过数据计算的摘要。
     *
     * @param digestName 摘要名称
     * @param data
     * @return
     * @throws NoSuchAlgorithmException
     */
    public static byte[] computeDigest(String digestName, byte[] data) throws
            NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance(digestName, new BouncyCastleProvider());
        digest.update(data);
        return digest.digest();
    }
}
