package net.yishanhe.ot;


import org.spongycastle.math.ec.ECPoint;
import org.spongycastle.util.BigIntegers;

import java.math.BigInteger;
import java.util.Arrays;

public class Util {

    public static int getByteLen(int bitLen) {
        return (bitLen+7)/8;
    }

    public static int getLeadingZeros(int bitLen) {
        return (bitLen%8==0)?0:8-bitLen%8;
    }

    public static String byteToBinaryString(byte b) {
        return String.format("%8s", Integer.toBinaryString(b & 0xFF)).replace(' ', '0');
    }

    public static String byteArrayToBinaryString(byte[] ba) {
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < ba.length; i++) {
            builder.append(byteToBinaryString(ba[i]));
        }
        return builder.toString();
    }

    public static byte[] xor(byte[] eHash, byte[] bytes) {
        int length;
        if(eHash.length<=bytes.length)
            length=eHash.length;
        else
            length=bytes.length;

        byte[] result = new byte[length];
        for (int i = 0; i < length; i++) {
            result[i] = (byte) (eHash[i] ^ bytes[i]);
        }
        return result;
    }

    public static byte[] expandByteArray(byte[] src, int desBitLen) {
        int desByteLen = getByteLen(desBitLen);

        if (src.length > desByteLen) {
            throw new IllegalArgumentException("Input bytes (" + src.length+ ") must not be longer than output bytes ("+ desByteLen +").");
        }
        int srcByteLen = src.length;
        byte[] des = new byte[desByteLen];
        // set 00 at the beginning.
        for (int i = 0; i < desByteLen-srcByteLen; i++) {
            des[i] = (byte) 0x00;
        }
        System.arraycopy(src, 0, des, desByteLen-srcByteLen, srcByteLen);
        return des;
    }

    public static byte[] expandByteArray(byte[] src, int desBitLen,  byte filling) {
        int desByteLen = getByteLen(desBitLen);

        if (src.length > desByteLen) {
            throw new IllegalArgumentException("Input bytes (" + src.length+ ") must not be longer than output bytes ("+ desByteLen +").");
        }
        int srcByteLen = src.length;
        byte[] des = new byte[desByteLen];
        // set 00 at the beginning.
        for (int i = 0; i < desByteLen-srcByteLen; i++) {
            des[i] = filling;
        }
        System.arraycopy(src, 0, des, desByteLen-srcByteLen, srcByteLen);
        return des;
    }

    public static byte[] expandByteArray(BigInteger bi, int desBitLen) {
        byte[] biByte = bi.toByteArray();
        // drop the first one
        if (bi.signum() == -1) {
//            System.out.println(Util.byteArrayToBinaryString(biByte));
//            System.out.println(bi.toString(2));
            if (biByte.length > desBitLen/8) {
                byte[] src = new byte[desBitLen/8];
                System.arraycopy(biByte,biByte.length-desBitLen/8,src,0,src.length);
                return src;
            } else {
                return expandByteArray(biByte, desBitLen, (byte)0xFF) ;
            }
        } else {
            if (biByte.length > desBitLen/8) {
                byte[] src = new byte[desBitLen/8];
                System.arraycopy(biByte,biByte.length-desBitLen/8,src,0,src.length);
                return src;
            } else {
                return expandByteArray(biByte, desBitLen, (byte)0x00) ;
            }
        }
//        if (biByte.length > desBitLen/8) {
//            byte[] src = new byte[desBitLen/8];
//            System.arraycopy(biByte,biByte.length-desBitLen/8,src,0,src.length);
//            return src;
//        } else {
//            return expandByteArray(biByte, desBitLen) ;
//        }
    }

    public static boolean getBit(int i, int leadingZeroes, byte[] str)  {
        return (str[(i+leadingZeroes) >>> 3] & (1 << (7-((i+leadingZeroes) & 7)))) != 0;
    }

    public static BigInteger ecPointToBI(ECPoint ecPoint){

        // getX, getY Deprecated.
        // Use getAffineXCoord(), or normalize() and getXCoord(), instead
        BigInteger ecX = ecPoint.normalize().getXCoord().toBigInteger();
        BigInteger ecY = ecPoint.normalize().getYCoord().toBigInteger();
        return ecX.xor(ecY);
    }

    public static int byteArrayToInt(byte[] b)
    {
        return   b[3] & 0xFF |
                (b[2] & 0xFF) << 8 |
                (b[1] & 0xFF) << 16 |
                (b[0] & 0xFF) << 24;
    }
    /**
     * Convert an integer into a byte array of 4 bytes.
     *
     * @param  a The integer to be converted
     */
    public static byte[] intToByteArray(int a)
    {
        return new byte[] {
                (byte) ((a >>> 24) & 0xFF),
                (byte) ((a >>> 16) & 0xFF),
                (byte) ((a >>> 8) & 0xFF),
                (byte) (a & 0xFF)
        };
    }

    public static String printBigIntegerMatrix(BigInteger[][] matrix){
        StringBuilder msgBuilder = new StringBuilder();
        for (int j = 0; j < matrix.length; j++) {
            for (int k = 0; k < matrix[0].length; k++) {
                msgBuilder.append(matrix[j][k].toString()+"\t");
            }
            msgBuilder.append("\n");
        }
        return msgBuilder.toString();
    }

    public static String printDimensions(byte[][][] input) {
        return input.length+"x"+input[0].length+"x"+input[0][0].length;
    }

    final protected static char[] hexArray = "0123456789ABCDEF".toCharArray();
    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for ( int j = 0; j < bytes.length; j++ ) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    public static BigInteger[][] sumBIMatrix(BigInteger[][] a, BigInteger[][] b) {
        int xlen = a.length;
        int ylen = a[0].length;
        BigInteger[][] result = new BigInteger[xlen][ylen];
        for (int i = 0; i < xlen; i++) {
            for (int j = 0; j < ylen; j++) {
                result[i][j] =  a[i][j].add(b[i][j]);
            }
        }
        return result;
    }

}
