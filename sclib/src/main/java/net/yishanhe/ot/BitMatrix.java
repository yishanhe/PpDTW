package net.yishanhe.ot;

import java.security.InvalidParameterException;

/**
 * Created by syi on 11/9/14.
 * This matrix is transposed at an early stage.
 * TODO: need a special bit matrix for OT and OT-Ext.
 * TODO: need setbit methods.
 */
public class BitMatrix {

    private byte[][] data;
    private int m; // m rows
    private int k; // k columns

    private int colLeadingZero;
    private int colByteLen;
    private int rowByteLen;
    private int rowLeadingZero;
    private byte[] masks;
    private boolean isTransposed = false;

    public BitMatrix(int m, int k) {

        this.m = m;
        this.k = k;

        this.colByteLen = Util.getByteLen(m);
        this.colLeadingZero = Util.getLeadingZeros(m);

        this.data = new byte[k][colByteLen];

        this.rowByteLen = Util.getByteLen(k);
        this.rowLeadingZero = Util.getLeadingZeros(k);

        initialiseMasks();

    }

    /**
     * provide a mask array for easy-access to bit in bytes.
     */
    private void initialiseMasks() {
        int Mask =128; // 2^7 1000 0000
        this.masks=new byte[8];
        for(int i=0;i<8;i++){
            this.masks[i]= (byte) (Mask>>>i);
        }

    }

    public void setData(byte[][] input) {
        if (input.length != k) {
            throw new IllegalArgumentException("The row length not match.");
        }
        // copy the data.
        for (int i = 0; i < k; i++) {
            if (input[i].length!=colByteLen) {
                throw new IllegalArgumentException(" The column length not match.");
            }
            System.arraycopy(input[i], 0, this.data[i], 0, colByteLen);
        }
    }

    public void setColumn(int i, byte[] input) {
        if (i < 0 || i >= k)
            throw new InvalidParameterException("i is out of range.");
        if (input.length != this.colByteLen)
            throw new InvalidParameterException("The size of the input array should be " + this.colByteLen + ".");
        this.data[i] = new byte[input.length];
        System.arraycopy(input, 0, this.data[i], 0, input.length);
    }

    public byte[] getColumn(int i){
        byte[] result = new byte[colByteLen];
        getColumn(i, result);
        return result;
    }

    public void getColumn(int i, byte[] result){
        if(i<0 || i>=k )
            throw new InvalidParameterException("i is out of range.");
        if (result.length!=colByteLen) {
            throw new InvalidParameterException("result length should be " +this.colByteLen + " bytes.");
        }
        System.arraycopy(this.data[i], 0, result, 0, colByteLen);
    }

    public byte[][] getData(){
        return this.data;
    }

    public void getData(byte[][] result){
        if (result.length != k) {
            throw new IllegalArgumentException("The row length not match.");
        }
        // copy the data.
        for (int i = 0; i < k; i++) {
            if (result[i].length!=colByteLen) {
                throw new IllegalArgumentException(" The column length not match.");
            }
            System.arraycopy(this.data[i], 0, result[i], 0, colByteLen);
        }
    }

    public int getM(){
        return this.m;
    }

    public int getK(){
        return this.k;
    }

    public byte[] getRow(int i) {

        byte[] result = new byte[this.rowByteLen];

        getRow(i, result);

        return result;
    }

    public void getRow(int i,byte[] outputRow){
        if(i<0 || i>=m)
            throw new InvalidParameterException("i is out of range.");
        if (outputRow.length!=this.rowByteLen)
            throw new InvalidParameterException("result length should be " +this.rowByteLen + " bytes.");

        int dataByteLoc = (i+this.colLeadingZero)>>>3;
        int dataBitLoc = (i+this.colLeadingZero)&7;

        // get one bit from each column and set the corresponding bit in the output bit

        byte[] rowBuffer = new byte[this.rowByteLen];

        int byteLoc;
        int bitInByte;
        int index;
        for(int j=0;j<this.k;j++){
            if((this.data[j][dataByteLoc]&this.masks[dataBitLoc])!=0){
                index=j+this.rowLeadingZero;
                byteLoc= index>>>3;
                bitInByte = index&7;
                rowBuffer[byteLoc]=(byte) (rowBuffer[byteLoc]|masks[bitInByte]);
            }
        }

        System.arraycopy(rowBuffer, 0, outputRow, 0, outputRow.length);

    }

    @Override
    public String toString() {
        StringBuilder stringBuilder = new StringBuilder();
        for (int i = 0; i < k; i++) {
            for (int j = 0; j < m; j++) {
                int dataByteLoc = (j+this.colLeadingZero)/8;
                int dataBitLoc = (j+this.colLeadingZero)%8;
                if((this.data[i][dataByteLoc]&this.masks[dataBitLoc])!=0){
                    stringBuilder.append("1");
                } else {
                    stringBuilder.append("0");
                }
            }
            stringBuilder.append("\n");
        }
        return stringBuilder.toString();
    }

    public void transpose() {
        byte[][] transposed = new byte[m][rowByteLen];

    }

    public void transposeInPlace() {}
}