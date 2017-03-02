package net.yishanhe.ot;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.math.BigInteger;
import java.util.Random;

import static org.junit.Assert.*;

/**
 * Created by syi on 7/15/16.
 */
public class UtilTest {
    byte[] ba;

    @Before
    public void setUp() throws Exception {
        ba = new byte[2];
        ba[0] = (byte) 0xFF;
        ba[1] = (byte) 0x00;

    }

    @Test
    public void testGetByteLen() throws Exception {
        int bitLen = 7;
        assertEquals(1, Util.getByteLen(bitLen));
        bitLen = 8;
        assertEquals(1, Util.getByteLen(bitLen));
        bitLen = 15;
        assertEquals(2, Util.getByteLen(bitLen));
        bitLen = 16;
        assertEquals(2, Util.getByteLen(bitLen));
        bitLen = 17;
        assertEquals(3, Util.getByteLen(bitLen));
    }

    @Test
    public void testGetLeadingZero() throws Exception {
        int bitLen = 7;
        assertEquals(1, Util.getLeadingZeros(bitLen));
        bitLen = 8;
        assertEquals(0, Util.getLeadingZeros(bitLen));
        bitLen = 15;
        assertEquals(1, Util.getLeadingZeros(bitLen));
        bitLen = 16;
        assertEquals(0, Util.getLeadingZeros(bitLen));
        bitLen = 17;
        assertEquals(7, Util.getLeadingZeros(bitLen));
    }

    @Test
    public void testExpandByteArray() throws Exception {
        System.out.println("** Test expandByteArray **");
        int msgBitLength = 25;
        BigInteger input = BigInteger.valueOf(-100); // sign bit here is used a value.
        byte[] expected = input.toByteArray();
        System.out.println("** input:" + input.toString() + " in bit string: " + Util.byteArrayToBinaryString(expected));
        byte[] expandedResult = Util.expandByteArray(input.toByteArray(), msgBitLength);
        BigInteger output = new BigInteger(1,expandedResult);
        System.out.println("** output:" + output.toString() + " expanded bit string:" + Util.byteArrayToBinaryString(expandedResult));
        assertEquals(new BigInteger(1,expected), output);
    }

    @Test
    public void testGetBit() throws Exception {
        int bitLen = 122;
        int byteLen = Util.getByteLen(bitLen);
        int leadingZeros = Util.getLeadingZeros(bitLen);
        byte[] testBa = new byte[byteLen];
        Random rnd = new Random();
        rnd.nextBytes(testBa);
        String expected = Util.byteArrayToBinaryString(testBa).substring(leadingZeros);
        StringBuilder testResult = new StringBuilder();
        for (int i = 0; i < bitLen; i++) {
            if (Util.getBit(i,leadingZeros,testBa)) {
                testResult.append("1");
            } else {
                testResult.append("0");
            }
        }
        assertEquals(expected, testResult.toString());
    }

    @Test
    public void testBigInteger() throws Exception {
        BigInteger a = BigInteger.valueOf(1).shiftLeft(31); // 32bit unsigned
        System.out.println(a.toByteArray().length);
        System.out.println(Util.byteArrayToBinaryString(a.toByteArray()));

        BigInteger b = BigInteger.valueOf(1).shiftLeft(30);
        System.out.println(b.toByteArray().length);
        System.out.println(Util.byteArrayToBinaryString(b.toByteArray()));
    }
}