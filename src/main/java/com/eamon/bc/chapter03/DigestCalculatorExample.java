package com.eamon.bc.chapter03;

import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;
import java.io.OutputStream;

import static com.eamon.bc.chapter03.Utils.createDigestCalculator;

/**
 * @author: eamon
 * @date: 2019-01-30 15:24
 * @description: Creation and use of a SHA-256 DigestCalculator
 */
public class DigestCalculatorExample {

    public static void main(String[] args) throws OperatorCreationException, IOException {
        DigestCalculator calculator = createDigestCalculator("SHA-256");
        OutputStream outputStream = calculator.getOutputStream();
        outputStream.write(Strings.toByteArray("Hello World!"));
        outputStream.close();
        System.out.println(Hex.toHexString(calculator.getDigest()));
    }
}
