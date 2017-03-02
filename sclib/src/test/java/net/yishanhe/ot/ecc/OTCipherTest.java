package net.yishanhe.ot.ecc;

import net.yishanhe.ot.Util;

import org.junit.Before;
import org.junit.Test;

import java.math.BigInteger;
import java.security.SecureRandom;

import static org.junit.Assert.*;

/**
 * Created by syi on 7/16/16.
 */
public class OTCipherTest {

    private OTCipher otOTCipher;
    private int msgLength;
    private BigInteger key;
    private SecureRandom rnd;

    @Before
    public void setUp() throws Exception {
        otOTCipher = new OTCipher();
        rnd = new SecureRandom();
    }

    @Test
    public void encryptAndDecryptNopadding() throws Exception {
        msgLength = 160; // same length as sha1.

        byte[] key = new byte[Util.getByteLen(msgLength)];
        byte[] msg = new byte[Util.getByteLen(msgLength)];
        rnd.nextBytes(key);
        rnd.nextBytes(msg);
        System.out.println("** input msg: "+new BigInteger(msg).toString()+" **");
        System.out.println("** key bytes len: "+key.length+" **");
        byte[] ct = otOTCipher.encrypt(0, key, msg, msgLength);
        byte[] pt = otOTCipher.decrypt(0, key, ct, msgLength);
        assertArrayEquals(pt, msg);
        System.out.println("** output msg: "+new BigInteger(pt).toString()+" **");
    }

    @Test
    public void encryptAndDecryptPadding() throws Exception {
        msgLength = 160; // same length as sha1.

        byte[] key = new byte[Util.getByteLen(msgLength*2)];
        byte[] msg = new byte[Util.getByteLen(msgLength*2)];
        rnd.nextBytes(key);
        rnd.nextBytes(msg);
        System.out.println("** input msg: "+new BigInteger(msg).toString()+" **");
        System.out.println("** key bytes len: "+key.length+" **");
        byte[] ct = otOTCipher.encrypt(0, key, msg, msgLength*2);
        byte[] pt = otOTCipher.decrypt(0, key, ct, msgLength*2);
        assertArrayEquals(pt, msg);
        System.out.println("** output msg: "+new BigInteger(pt).toString()+" **");
    }

    @Test
    public void paddingLength() throws Exception {
        System.out.println("** Test padding length **");
        msgLength = 160; // same length as sha1.

        byte[] key = new byte[Util.getByteLen(msgLength)];
        byte[] msg = new byte[Util.getByteLen(msgLength)];
        rnd.nextBytes(key);
        rnd.nextBytes(msg);
        System.out.println("** input msg: "+new BigInteger(msg).toString()+" **");
        System.out.println("** key bytes len: "+key.length+" **");
        byte[] ct = otOTCipher.encrypt(0, key, msg, msgLength);
        System.out.println("** ct bytes len: "+ct.length+" **");
        byte[] pt = otOTCipher.decrypt(0, key, ct, msgLength);
        assertArrayEquals(pt, msg);
        System.out.println("** pt bytes len: "+pt.length+" **");
        System.out.println("** output msg: "+new BigInteger(pt).toString()+" **");
    }

    @Test
    public void ByteOperation() throws Exception {
        byte ONE = (byte)0x01;
        byte ZERO = (byte)0x00;
        System.out.println("0 and 1 in bytes: "+(int) ONE+","+(int) ZERO);
    }
}