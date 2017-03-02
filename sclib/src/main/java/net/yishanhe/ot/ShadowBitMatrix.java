package net.yishanhe.ot;

import java.security.InvalidParameterException;

/**
 * Created by syi on 11/9/14.
 * This matrix is transposed at an early stage.
 * TODO: need a special bit matrix for OT and OT-Ext.
 */
public class ShadowBitMatrix {

    private int m; // m rows
    private int k; // k columns
    private BitMatrix bitMatrix;
    private BitMatrix shadowBitMatrix;


    public ShadowBitMatrix(int m, int k) {
        this.k = k;
        this.m = m;
        bitMatrix = new BitMatrix(m, k);
        shadowBitMatrix = new BitMatrix(m, k);
    }

}

