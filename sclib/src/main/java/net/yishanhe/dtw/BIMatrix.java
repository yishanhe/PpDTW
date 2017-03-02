package net.yishanhe.dtw;

import java.math.BigInteger;

/**
 * Created by syi on 11/12/14.
 * this matrix is used as the dynamic programming matrix
 * to get the result of a dynamic programming algorithm.
 */
public class BIMatrix {

    private BigInteger[][] data;
    private int nRow;
    private int nCol;

    public BIMatrix(int nRow, int nCol) {
        this.nRow = nRow;
        this.nCol = nCol;
        this.data = new BigInteger[nRow][nCol];
        for (int i = 0; i < nRow; i++) {
            for (int j = 0; j < nCol; j++) {
               data[i][j] = BigInteger.ZERO;
            }
        }
    }

    public BigInteger getItem(int x, int y) {
        // TODO: need to validate x and y
        return data[x][y];
    }

    public void setItem(BigInteger item, int x, int y) {
        this.data[x][y] = BigInteger.ZERO.add(item);
    }

    public BigInteger[] getTriple(int x, int y){
        BigInteger[] result = new BigInteger[3];
        result[0] = this.data[x-1][y-1];
        result[1] = this.data[x-1][y];
        result[2] = this.data[x][y-1];
        return result;
    }

    public void setRow(int row, BigInteger[] rowData){
        if ( row<0 || row >= nRow) {
            System.out.println("wrong argument.");
        }

        for (int i = 0; i < nCol; i++) {
            this.setItem(rowData[i], row, i);
        }
    }

    public BigInteger[][] getData() {
        return data;
    }

    public int getNumRow() {
        return nRow;
    }

    public int getRowLen() {
        return  nCol;
    }

    public int getNumCol() {
        return nCol;
    }

    public int getColLen() {
        return nRow;
    }
}
