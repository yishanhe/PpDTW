package net.yishanhe.ot;

import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.*;

/**
 * Created by syi on 7/15/16.
 * This context of column and row is exchanged in this class.
 * bit matrix [k][m]
 * k is number of column
 * m is the number of row
 */
public class BitMatrixTest {

    int k;
    int m;
    BitMatrix matrix;

    @Before
    public void setUp() throws Exception {
        k = 8;
        m = 8;

        matrix = new BitMatrix(m,k);

        byte[][] data = new byte[k][1];

        for (int i = 0; i < k; i++) {
            if (i%2 == 0) {
                data[i][0] = (byte)0xFF;
            } else {
                data[i][0] = (byte)0x00;
            }
        }
        matrix.setData(data);
        System.out.println(matrix.toString());
        System.out.println();
    }

    @Test
    public void testSetColumn() throws Exception {
        System.out.println(this.matrix.toString());
        byte[] bytes0 = new byte[]{(byte)0x00};
        for (int i = 0; i < k; i++) {
           if (i%2 ==0) {
               matrix.setColumn(i, bytes0);
           }
        }
        System.out.println(this.matrix.toString());
    }

    @Test
    public void testGetColumn() throws Exception {
        byte[] bytes1 = new byte[]{(byte)0xFF};
        byte[] bytes0 = new byte[]{(byte)0x00};

        for (int i = 0; i < k; i++) {
           if (i%2 ==0) {
               assertArrayEquals(bytes1, matrix.getColumn(i));
           } else {
               assertArrayEquals(bytes0, matrix.getColumn(i));
           }
        }
    }

    @Test
    public void testGetRow() throws Exception {
        byte[] row = new byte[]{(byte)0xAA};
        for (int i = 0; i < m; i++) {
            System.out.println(Util.byteArrayToBinaryString(matrix.getRow(i)));
            assertArrayEquals(row, matrix.getRow(i));
        }
    }

}