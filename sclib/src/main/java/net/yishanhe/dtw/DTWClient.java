package net.yishanhe.dtw;

import net.yishanhe.he.PrimePaillier;
import net.yishanhe.ot.Util;

import org.spongycastle.util.BigIntegers;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * Created by syi on 7/19/16.
 */
public class DTWClient {

    static int TRIPLE_SIZE = 3;
    static int[] TRIPLE_IDX = {0,1,2};
    List<Integer> tripleIndexList;

    public ArrayList<BigInteger> rDTW = new ArrayList<>();
    int xsLen;
    int ysLen;
    int[] xs;
    SecureRandom rnd;
    public BIMatrix cDistMatrix; // c = complete matrix, matrix splitting techniques.
    public BIMatrix cEncDistMatrix; // in cipher text of cipher.
    PrimePaillier cipher = null;
    BigInteger[][] rSums;
    public BigInteger[] tripleDiffPermutedCT;
    public BigInteger[] triplePermutedCT;
    public BigInteger[] triplePermutedOT;

    public DTWClient(int[] xs, PrimePaillier cipher) {
        this.xs = xs;
        this.xsLen = xs.length;
        this.rnd = new SecureRandom();
        this.cipher = cipher;
    }

    public DTWClient(int[] xs, PrimePaillier.PublicKey publicKey) {
        this.xs = xs;
        this.xsLen = xs.length;
        this.rnd = new SecureRandom();
        this.cipher = new PrimePaillier(publicKey);
    }

    public DTWClient(int[] xs, PrimePaillier.PublicKey publicKey, PrimePaillier.PrivateKey privateKey) {
        this.xs = xs;
        this.xsLen = xs.length;
        this.rnd = new SecureRandom();
        this.cipher = new PrimePaillier(publicKey, privateKey);
    }

//    public void onReceivePublicKey(PrimePaillier.PublicKey publicKey) {
//        cipher = new PrimePaillier(publicKey);
////        System.out.println(publicKey.getG().toString());
////        System.out.println(publicKey.getN().toString());
////        System.out.println(publicKey.getNSquare().toString());
//    }

    public void onReceiveR(BigInteger[][] rSums) {
        this.rSums = rSums;

        if (cipher == null) {
            throw new IllegalArgumentException("Need public key first.");
        }

        if (rSums.length != xs.length) {
            throw new IllegalArgumentException("Input xs length no match with rSums.");
        }
        this.ysLen = rSums[0].length;

        // get cDistMatrix
        cDistMatrix = new BIMatrix(xsLen, ysLen);
        cEncDistMatrix = new BIMatrix(xsLen, ysLen);

        BigInteger tmp = BigInteger.ZERO;
        BigInteger rTmp = BigInteger.ZERO;
        for (int i = 0; i < xsLen; i++) {
            // set y == 0 cases
            tmp = tmp.add(BigInteger.valueOf(this.xs[i]*this.xs[i]));
            rTmp = rTmp.add(rSums[i][0]);
            cDistMatrix.setItem(tmp.subtract(rTmp), i, 0);
//            System.out.println(cDistMatrix.getItem(i,0).toString());
//            System.out.println(Util.bytesToHex(cDistMatrix.getItem(i,0).toByteArray()));
//            System.out.println(Util.bytesToHex(cipher.encrypt(cDistMatrix.getItem(i,0)).toByteArray()));
            cEncDistMatrix.setItem( cipher.encrypt(cDistMatrix.getItem(i,0)), i,0);
        }

        rTmp = rSums[0][0];
        for (int i = 1; i < ysLen; i++) {
            // set x == 0 cases
            // avoid the first one
            rTmp = rTmp.add(rSums[0][i]);
            cDistMatrix.setItem(BigInteger.valueOf(this.xs[0]*this.xs[0]*(i+1)).subtract(rTmp), 0, i);
            cEncDistMatrix.setItem( cipher.encrypt(cDistMatrix.getItem(0, i)), 0, i);
        }

        // set other cases
        for (int i = 1; i < xsLen; i++) {
            for (int j = 1; j < ysLen; j++) {
                // TODO: check this can be skipped.
//                cDistMatrix.setItem(BigInteger.valueOf(this.xs[i]*this.xs[i]).subtract(rSums[i][j]), i, j);
//                cEncDistMatrix.setItem( cipher.encrypt(cDistMatrix.getItem(i, j)), i, j);
            }
        }

//        System.out.println(Util.printBigIntegerMatrix(cDistMatrix.getData()));
//        System.out.println(Util.printBigIntegerMatrix(cEncDistMatrix.getData()));
    }

    public BigInteger genR() {
        byte[] rndBuffer = new byte[4];
        rnd.nextBytes(rndBuffer);
        // TODO
        return new BigInteger(rndBuffer);
    }

    public BigInteger[] sendTripleDiffCT() {
        return this.tripleDiffPermutedCT;
    }
    // non-batched iteration.
    public void onReceiveTriple(BigInteger[] remoteTriple, int i, int j, byte[][][] input) {
        if (cipher == null) {
            throw new IllegalArgumentException("Paillier ciphter not initialized.");
        }
        // get corresponding part
        BigInteger[] localTriple = this.cEncDistMatrix.getTriple(i,j);
        // TODO:
        BigInteger[] tripleCT = new BigInteger[TRIPLE_SIZE];
        this.tripleIndexList = new ArrayList<Integer>(TRIPLE_SIZE);

        for (int k = 0; k < TRIPLE_SIZE; k++) {
            tripleCT[k] = cipher.add(localTriple[k], remoteTriple[k]);
//            System.out.println(k+"th decrypted localTriple: "+cipher.decrypt(localTriple[k]).toString());
//            System.out.println(k+"th decrypted remoteTriple: "+cipher.decrypt(remoteTriple[k]).toString());
//            System.out.println(k+"th decrypted tripleCT: "+cipher.decrypt(tripleCT[k]).toString());
//            System.out.println(k+"th decrypted tripleCT:"+cipher.decrypt(tripleCT[k]).toString());
            this.tripleIndexList.add(k, TRIPLE_IDX[k]);
        }
//        System.out.println("decrypted tripleCT: " +cipher.decrypt(tripleCT[0])+","+cipher.decrypt(tripleCT[1])+","+cipher.decrypt(tripleCT[2]));

        // permutation,
        Collections.shuffle(this.tripleIndexList);
        tripleDiffPermutedCT = new BigInteger[TRIPLE_SIZE];
        triplePermutedCT = new BigInteger[TRIPLE_SIZE];

        // generate the permuted and diff-permuted
        for (int k = 0; k < TRIPLE_SIZE; k++) {
            triplePermutedCT[k] = tripleCT[this.tripleIndexList.get(k)];
//            System.out.println(triplePermutedCT[k].toString());
        }
//        System.out.println("decrypted shuffled tripleCT: " +cipher.decrypt(triplePermutedCT[0])+","+cipher.decrypt(triplePermutedCT[1])+","+cipher.decrypt(triplePermutedCT[2]));

        tripleDiffPermutedCT[0] = cipher.subtract(triplePermutedCT[0], triplePermutedCT[1]);
        tripleDiffPermutedCT[1] = cipher.subtract(triplePermutedCT[0], triplePermutedCT[2]);
        tripleDiffPermutedCT[2] = cipher.subtract(triplePermutedCT[1], triplePermutedCT[2]);
//        System.out.println("shuffled index: " + Arrays.toString(this.tripleIndexList.toArray()));
//        System.out.println("decrypted diffPermuted:" +cipher.decrypt(tripleDiffPermutedCT[0])+", "+cipher.decrypt(tripleDiffPermutedCT[1])+", "+cipher.decrypt(tripleDiffPermutedCT[2]));
        // prepare  R_new - R_old version as permuted.
//        BigInteger newR = genR();
        BigInteger newR = BigInteger.ZERO;
//        rDTW.add(newR);
        // cDistMatrix.setItem(BigInteger.valueOf(this.xs[i]*this.xs[i]).subtract(rSums[i][j]), i, j);
        // cEncDistMatrix.setItem( cipher.encrypt(cDistMatrix.getItem(i, j)), i, j);
        this.cDistMatrix.setItem(BigInteger.valueOf(this.xs[i]*xs[i]).subtract(newR), i, j);
        this.cEncDistMatrix.setItem(cipher.encrypt(cDistMatrix.getItem(i, j)), i, j);

        BigInteger newRminusOldR = newR.subtract(rSums[i][j]);
        rSums[i][j] = newR;
        // update matrix

        BigInteger newRminusOldRinCT = cipher.encrypt(newRminusOldR);
//        System.out.println("**client** new rand is "+newRminusOldR);

        // get differences and random scaling
        // TODO: add random scaling positive.
        triplePermutedOT = new BigInteger[TRIPLE_SIZE];
        for (int k = 0; k < TRIPLE_SIZE; k++) {
            triplePermutedOT[k] = cipher.add(triplePermutedCT[k], newRminusOldRinCT);
            // copy
//            byte[] bytebuffer = triplePermutedOT[k].toByteArray();
//            byte[] bytebuffer = Util.expandByteArray(BigIntegers.asUnsignedByteArray(triplePermutedOT[k]),1024);
            byte[] bytebuffer = Util.expandByteArray(triplePermutedOT[k], 1024);

            if (bytebuffer.length*8 > 1024) {
                System.out.println(bytebuffer.length*8+" bits");
                System.out.println(triplePermutedOT[k].toString(2));
                System.out.println(Util.byteArrayToBinaryString(bytebuffer));
            }
            System.arraycopy(bytebuffer, 0, input[0][k], 0, bytebuffer.length);
        }
    }

    // batched iteration
}
