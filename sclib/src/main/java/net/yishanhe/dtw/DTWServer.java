package net.yishanhe.dtw;

import net.yishanhe.he.PrimePaillier;
import net.yishanhe.ot.Util;

import org.spongycastle.util.BigIntegers;

import java.math.BigInteger;

/**
 * Created by syi on 7/19/16.
 */
public class DTWServer {

    static int TRIPLE_SIZE = 3;
    private PrimePaillier cipher = null;
    private int xsLen;
    private int ysLen;
    public BIMatrix cDistMatrix;
    public BIMatrix cEncDistMatrix;
    private int[] ys;

    public DTWServer(int[] ys, PrimePaillier cipher) {
        this.ys = ys;
        this.ysLen = ys.length;
        this.cipher = cipher;
    }

    /**
     * RcMatrix is the cipher encrypted -Rij+Rc cipher text.
     */
    public void onReceiveOTDistMatrix(BigInteger[][] otDistMatrix) {
        if (cipher == null) {
            throw new IllegalArgumentException("Prime Paillier not init.");
        }
        if (otDistMatrix[0].length!=ysLen) {
            throw new IllegalArgumentException("ys length not match dist matrix");
        }
        this.xsLen = otDistMatrix.length;

        cDistMatrix = new BIMatrix(xsLen, ysLen);
        cEncDistMatrix = new BIMatrix(xsLen, ysLen);


        // [0,0] separately
        cDistMatrix.setItem(otDistMatrix[0][0], 0, 0);
        cEncDistMatrix.setItem( cipher.encrypt(cDistMatrix.getItem(0,0)), 0,0);

        for (int i = 1; i < xsLen; i++) {
            // set y == 0 cases
            BigInteger tmp = otDistMatrix[i][0].add(cDistMatrix.getItem(i-1,0));
            cDistMatrix.setItem(tmp, i, 0);
//            System.out.println(Util.bytesToHex(cDistMatrix.getItem(i,0).toByteArray()));
//            System.out.println(Util.bytesToHex(cipher.encrypt(cDistMatrix.getItem(i,0)).toByteArray()));
            cEncDistMatrix.setItem( cipher.encrypt(cDistMatrix.getItem(i,0)), i,0);
        }

        for (int i = 1; i < ysLen; i++) {
            // set x == 0 cases
            // avoid the first one
            BigInteger tmp = otDistMatrix[0][i].add(cDistMatrix.getItem(0, i-1));
            cDistMatrix.setItem(tmp, 0, i);
            cEncDistMatrix.setItem( cipher.encrypt(cDistMatrix.getItem(0, i)), 0, i);
        }

        // set other cases
        for (int i = 1; i < xsLen; i++) {
            for (int j = 1; j < ysLen; j++) {
                cDistMatrix.setItem(otDistMatrix[i][j], i, j);
                cEncDistMatrix.setItem( cipher.encrypt(cDistMatrix.getItem(i, j)), i, j);
            }
        }
//        System.out.println(Util.printBigIntegerMatrix(cDistMatrix.getData()));
//        System.out.println(Util.printBigIntegerMatrix(cEncDistMatrix.getData()));
    }

//    public PrimePaillier.PublicKey sendPublicKey() {
//        System.out.println("Paillier nSquare: " + cipher.getKeyPair().getPublicKey().getNSquare().toString());
//        return cipher.getKeyPair().getPublicKey();
//    }

//    public void prepare() {
//        cipher = new PrimePaillier(512, 128);
//    }

    public BigInteger[] sendTriple(int i, int j) {
        BigInteger[] tripleCT = cEncDistMatrix.getTriple(i,j);
//        System.out.println("**Server** decrypted toSendTripleCT: " +cipher.decrypt(tripleCT[0])+","+cipher.decrypt(tripleCT[1])+","+cipher.decrypt(tripleCT[2]));
        return cEncDistMatrix.getTriple(i, j);
    }

    // non-batched iteration
    public int[] onReceiveTripleDiffCT(BigInteger[] tripleDiffPermutedCT) {
        int min;

        BigInteger sign = cipher.decrypt(tripleDiffPermutedCT[0]);

        if (sign.signum() == -1) {
            sign = cipher.decrypt(tripleDiffPermutedCT[1]);
            if (sign.signum() == -1) {
                min = 0;
            } else {
                min = 2;
            }
        } else {
            sign = cipher.decrypt(tripleDiffPermutedCT[2]);
            if (sign.signum() == -1) {
                min = 1;
            } else {
                min = 2;
            }
        }

        int[] result = new int[1];
        result[0] = min;
//        System.out.println("**Server** the min index is "+min);
        return result;
    }

    public void onTripleOTResult(byte[][] otResult, int i, int j) {
        if (otResult.length!=1) {
            throw new IllegalArgumentException("length not match.");
        }
        BigInteger ct = new BigInteger(1,otResult[0]);
//        BigInteger ct = BigIntegers.fromUnsignedByteArray(otResult[0]);
        onTripleOTResult(ct, i, j);
    }
    public void onTripleOTResult(BigInteger CT, int i, int j) {
//        System.out.println("**Server** "+i+","+j+" origin: "+cipher.decrypt(this.cEncDistMatrix.getItem(i,j)));
//        System.out.println("**Server** "+i+","+j+" add in ct: "+cipher.decrypt(CT));
        BigInteger updatedItem = cipher.add(CT, this.cEncDistMatrix.getItem(i, j));
//        System.out.println("**Server** "+i+","+j+" updated: "+cipher.decrypt(updatedItem));
        this.cEncDistMatrix.setItem(updatedItem, i, j);
    }

    // batched iteration
    // TODO: Implement the batched iteration.
    public int[] onReceiveTripleDiffCTs(BigInteger[][] tripleDiffPermutedCT) {
        return null;
    }
}
