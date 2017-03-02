package net.yishanhe.ot.prime;

import net.yishanhe.ot.Util;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * Created by syi on 7/21/16.
 */
public class PrimeNOTS {

    private BigInteger p; // group
    private BigInteger q; // subgroup
    private BigInteger g; // generator

    private int k; // rounds of OT.
    private int N; // 1-out-of-n OT.
    private BigInteger r;
    private BigInteger[] cs; // N  [0, 1 -> N-1], first is g,
    private BigInteger[] crs; // N []
    //    private BigInteger[] grs; // k

    private byte[] nonce;
    private MessageDigest H; // Hash for generate seeds

    /**
     * TODO: R for everytime reusing.
     * @param p
     * @param q
     * @param g
     * @param k
     * @param N
     */
    public PrimeNOTS(BigInteger p, BigInteger q, BigInteger g, int k, int N) {
        this.p = p;
        this.q = q;
        this.g = g;
        this.k = k;
        this.N = N;
        try {
            this.H = MessageDigest.getInstance("SHA-1");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        this.cs = new BigInteger[N]; // there two will be resued every time.
        this.crs = new BigInteger[N];
    }

    public void prepare() {
        // init cs, cs[0] will store g^r
        // this set of parameter will not change in the following run.
        SecureRandom rnd = new SecureRandom();
        for (int i = 0; i < N; i++) {

            do {
                // use crs[0] as buffer to generate cs
                this.crs[0] = new BigInteger(this.q.bitLength(), rnd);
            } while (this.crs[0].subtract(this.q).signum()>=0);

            // generate r
            if( i == 0 ){
                this.r = this.crs[0];
            }

            // cs = [g^r, c1,c2,...,cN-1]
            this.cs[i] = this.g.modPow(this.crs[0], this.p);

            // pre-computing Ci^r for i = 1 ... N-1
            if( i == 0 ){
                this.crs[i] = this.cs[i];
            } else {
                this.crs[i] = this.cs[i].modPow(this.r, this.p);
            }
        }


    }

    public BigInteger[] sendCs() {
        return this.cs;
    }

    public void onReceivePK0s(BigInteger[] PK0s, byte[][][] input, byte[][][] output, byte[] nonce) {
        SecureRandom KDF;
        for (int i = 0; i < k; i++) {
            // PK0->PK0^r
            BigInteger pk0r = PK0s[i].modPow(this.r, this.p);
            this.H.update(pk0r.toByteArray());
            // H(PK0^r,0,R)
            this.H.update(ByteBuffer.allocate(4).putInt(0).array());
            this.H.update(nonce);
            byte[] keyFromKDF = new byte[input[0][0].length];
            byte[] seed = this.H.digest();
            KDF = getRndInstance(seed);
//            System.out.println("OTS seed: "+Util.bytesToHex(seed));
            KDF.nextBytes(keyFromKDF);
            output[i][0] = Util.xor(input[i][0], keyFromKDF);
//            System.out.println("OTS: "+Util.bytesToHex(keyFromKDF));

            // get all other pk_i, i = 1 ... N-1, (pk_i)^r
            for (int j = 1; j < N; j++) {
                BigInteger pkjr = this.crs[j].multiply(pk0r.modInverse(this.p)).mod(this.p);
                this.H.update(pkjr.toByteArray());
                this.H.update(ByteBuffer.allocate(4).putInt(j).array());
                this.H.update(nonce);
                // KDF
                keyFromKDF = new byte[input[0][0].length];
//                System.out.println(input[0][0].length);
                seed = this.H.digest();
                KDF = getRndInstance(seed);
//                System.out.println("OTS seed: "+Util.bytesToHex(seed));
                KDF.nextBytes(keyFromKDF);
//                System.out.println("OTS: "+Util.bytesToHex(keyFromKDF));
                output[i][j] = Util.xor(input[i][j], keyFromKDF);
            }

        }
    }

    public SecureRandom getRndInstance(byte[] seed) {
        try {
            SecureRandom rnd = SecureRandom.getInstance("SHA1PRNG");
            rnd.setSeed(seed);
            return rnd;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }
}
