package com.eamon.bc.chapter08;

import java.math.BigInteger;
import java.util.Date;

/**
 * @author: eamon
 * @date: 2019-01-31 17:39
 * @description:
 */
public class Utils {

    private static long serialNumberBase = System.currentTimeMillis();

    /**
     * Calculate a date in seconds (suitable for the PKIX profile - RFC 5280)
     *
     * @param hoursInFuture hours ahead of now, may be negative.
     * @return
     */
    public static Date calculateDate(int hoursInFuture) {
        long secs = System.currentTimeMillis() / 1000;
        return new Date((secs + (hoursInFuture * 60 * 60)) * 1000);
    }

    /**
     * Calculate a serial number using a monotonically increasing value
     *
     * @return a BigInteger representing the next serial number in the sequence
     */
    public static BigInteger calculateSerialNumber() {
        return BigInteger.valueOf(serialNumberBase++);
    }



}
