package net.yishanhe.ot.ecc;

import net.yishanhe.ot.Util;

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.Security;
import java.util.logging.ConsoleHandler;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Copyright (C) 2014 by Yan Huang <yhuang@virginia.edu>
 *
 * Adopted and modified by Shanhe Yi <syi@cs.wm.edu> on 4/24/16.
 * Using a SHA-1 as a block cipher
 */
public class OTCipher {
    private static final Logger logger = Logger.getLogger(OTCipher.class.getName());

    private static final int blockCipherBitLen = 160; // SHA-1 has 160bits output
    private static final int blockCipherByteLen = Util.getByteLen(blockCipherBitLen); // SHA-1 has 20bytes

    private MessageDigest sha1;

    public OTCipher() {
        ConsoleHandler ch = new ConsoleHandler();
        ch.setLevel(Level.FINEST);
        logger.addHandler(ch);
        logger.setLevel(Level.FINEST);

        try {
            sha1 = MessageDigest.getInstance("SHA-1"); // 160bits
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
        }
    }


    // @TODO need to find a clever way to do the enc/dec with padding.

    public byte[] encrypt(int j, byte[] key, byte[] msg, int msgBitLen) {
//        System.out.println("Input pt bits:" + msg.length*8
//                + ", Output ct bits:" + msgBitLen
//                + ", Hash block width:" + blockCipherBitLen);
        byte[] expandedMsg = Util.expandByteArray(msg, msgBitLen);
        byte[] expandedKey = getPaddingOfLength(j, key, msgBitLen);
        // TODO: add Protocol 3.1 in Benny Pinkas Efficient OT. the R.
        return Util.xor(expandedMsg, expandedKey) ;
    }

    public byte[] encrypt(int j, byte[] key, byte[] msg, int msgBitLen, byte[] nonce) {
//        System.out.println("Input pt bits:" + msg.length*8
//                + ", Output ct bits:" + msgBitLen
//                + ", Hash block width:" + blockCipherBitLen);
        byte[] expandedMsg = Util.expandByteArray(msg, msgBitLen);
        byte[] expandedKey = getPaddingOfLength(j, key, msgBitLen, nonce);
        // TODO: add Protocol 3.1 in Benny Pinkas Efficient OT. the R.
        return Util.xor(expandedMsg, expandedKey) ;
    }


    public byte[] decrypt(int j, byte[] key, byte[] cph, int ctBitLen) {
//        System.out.println("Input ct bits:" + cph.length*8
//                + ", Output pt bits:" + ctBitLen
//                + ", Hash block width:" + blockCipherBitLen);
        if (ctBitLen < cph.length * 8 ) {
            throw new IllegalArgumentException("Output bit less than input.");
        }

        byte[] expandedMsg = Util.expandByteArray(cph, ctBitLen);
//        System.out.println(Util.byteArrayToBinaryString(cph) + " vs " + Util.byteArrayToBinaryString(expandedMsg));

        byte[] expandedKey = getPaddingOfLength(j, key, ctBitLen);

//        System.out.println(Util.byteArrayToBinaryString(key) + " vs " + Util.byteArrayToBinaryString(expandedKey));

        return Util.xor(expandedMsg, expandedKey) ;
    }

    public byte[] decrypt(int j, byte[] key, byte[] cph, int ctBitLen, byte[] nonce) {
//        System.out.println("Input ct bits:" + cph.length*8
//                + ", Output pt bits:" + ctBitLen
//                + ", Hash block width:" + blockCipherBitLen);
        if (ctBitLen < cph.length * 8 ) {
            throw new IllegalArgumentException("Output bit less than input.");
        }

        byte[] expandedMsg = Util.expandByteArray(cph, ctBitLen);
//        System.out.println(Util.byteArrayToBinaryString(cph) + " vs " + Util.byteArrayToBinaryString(expandedMsg));

        byte[] expandedKey = getPaddingOfLength(j, key, ctBitLen, nonce);

//        System.out.println(Util.byteArrayToBinaryString(key) + " vs " + Util.byteArrayToBinaryString(expandedKey));

        return Util.xor(expandedMsg, expandedKey) ;
    }

    /**
     *
     * @param key Used by encryption/decryption.
     *            The key will be expanded to the length of hash.
     *
     * The sha1 has 20bytes(160bits) but the message usually is longer than that.
     *
     * However, we try to use ECC. That would be 160 bits. (@TODO need a test)
     * If using prime number cryptosystem, like 1024bits. The hash is used as a block cipher.
     * E.g.  1024bits needs 7 hashes (7*160 = 1120).
     *
     * @param padLength The message length. The hash will be used as block by block
     *                  processing if message length is longer than the hash block width.
     *
     * @return
     */
    private byte[] getPaddingOfLength(int j, byte[] key, int padLength) {

        sha1.update(ByteBuffer.allocate(4).putInt(j).array());
        sha1.update(key);

        /**
         * e.g. if padLength = 160, 20bytes
         * byte[] pad 20 bytes
         */
        byte[] pad = new byte[(padLength-1)/8 + 1]; // convert padLength to number of bytes
        byte[] tmp;
        tmp = sha1.digest();
//        System.out.println("sha1 digest:"+Util.byteArrayToBinaryString(tmp));

        int i = 0;
        for (i = 0; i < (pad.length-1)/ blockCipherByteLen; i++) { // block cipher, calculate number of blocks needed.
            System.arraycopy(tmp, 0, pad, i* blockCipherByteLen, blockCipherByteLen);
            sha1.update(tmp);
            tmp = sha1.digest();
        }
        System.arraycopy(tmp, 0, pad, i* blockCipherByteLen, pad.length-i* blockCipherByteLen);
        return pad;
    }

    private byte[] getPaddingOfLength(int j, byte[] key, int padLength, byte[] nonce) {

        sha1.update(ByteBuffer.allocate(4).putInt(j).array());
        sha1.update(nonce);
        sha1.update(key);

        /**
         * e.g. if padLength = 160, 20bytes
         * byte[] pad 20 bytes
         */
        byte[] pad = new byte[(padLength-1)/8 + 1]; // convert padLength to number of bytes
        byte[] tmp;
        tmp = sha1.digest();
//        System.out.println("sha1 digest:"+Util.byteArrayToBinaryString(tmp));

        int i = 0;
        for (i = 0; i < (pad.length-1)/ blockCipherByteLen; i++) { // block cipher, calculate number of blocks needed.
            System.arraycopy(tmp, 0, pad, i* blockCipherByteLen, blockCipherByteLen);
            sha1.update(tmp);
            tmp = sha1.digest();
        }
        System.arraycopy(tmp, 0, pad, i* blockCipherByteLen, pad.length-i* blockCipherByteLen);
        return pad;
    }

    /**
     * when you get a plain text decrypted, since there is a padding scheme,
     * this method will be used to de-pad the plain text.
     * @param pt
     * @return
     */
    public byte[] dePadding(byte[] pt, int expectedBits) {
        int expectedBytes = Util.getByteLen(expectedBits);
        byte[] depadded = new byte[Util.getByteLen(expectedBits)];
        System.arraycopy(pt, pt.length-depadded.length, depadded, 0, depadded.length);
        return depadded;
    }

}
