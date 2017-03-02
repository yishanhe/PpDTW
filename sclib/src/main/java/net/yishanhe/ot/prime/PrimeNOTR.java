package net.yishanhe.ot.prime;

import net.yishanhe.ot.Util;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * Created by syi on 7/21/16.
 * follow implementation on Naor&Pinkas Protocol 3.1
 */
public class PrimeNOTR {


    private BigInteger p;
    private BigInteger q;
    private BigInteger g;

    private int[] s;
    private int k;
    private SecureRandom rnd;
    private BigInteger[] ks; // random k
    private BigInteger[] PK0s;
    private BigInteger[] cs;
    private BigInteger dk; // decryption key (g^r)^k
    private int N;

    private MessageDigest H; // Hash for generate seeds
//    private boolean init = false;

    public PrimeNOTR(BigInteger p, BigInteger q, BigInteger g, int k, int N) {
        this.p = p;
        this.q = q;
        this.g = g;
        this.k = k; // sLen
        this.N = N;

        try {
            this.H = MessageDigest.getInstance("SHA-1");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        this.ks = new BigInteger[k];
        this.PK0s = new BigInteger[k];
        this.rnd = new SecureRandom();
    }

//    public void setS(int[] s) {
//        if (k!=s.length) {
//            throw new IllegalArgumentException("Input Length Not Match.");
//        }
//        this.s = s;
//    }


    public void onReceiveCs(BigInteger[] cs) {

//        if (init) {
//            System.out.println("Redundant init. Check protocol!");
//        }
        this.cs = cs; // save this for further usage.

        // get Pk0s
//        for (int i = 0; i < k; i++) {
//            // get a random k
//            do{
//                this.ks[i] = new BigInteger(this.q.bitLength(),rnd);
//            } while (this.ks[i].subtract(q).signum() >= 0);
//
//            this.dk = this.g.modPow(this.ks[i], this.p); // g^k
//
//            if ( this.s[i] == 0 ) {
//                // pk0 = dk
//                PK0s[i] = this.dk;
//            } else {
//                // ci/dk
//                PK0s[i] = cs[s[i]].multiply(this.dk.modInverse(this.p)).mod(this.p);
//            }
//        }

//        this.init = true;
    }

    public void init(int[] s) {
        if (k!=s.length) {
            throw new IllegalArgumentException("Input Length Not Match.");
        }
        this.s = s;

//        if (!init) {
//            System.out.println("Need init first. Check protocol!");
//        }

        // update Pk0s
        for (int i = 0; i < k; i++) {
            // get a random k
            do{
                this.ks[i] = new BigInteger(this.q.bitLength(),rnd);
            } while (this.ks[i].subtract(q).signum() >= 0);

            this.dk = this.g.modPow(this.ks[i], this.p); // g^k

            if ( this.s[i] == 0 ) {
                // pk0 = dk
                PK0s[i] = this.dk;
            } else {
                // ci/dk
                PK0s[i] = cs[this.s[i]].multiply(this.dk.modInverse(this.p)).mod(this.p);
            }
        }
    }

    public BigInteger[] sendPK0s() {
        return PK0s;
    }

    public void onReceiveEncrypted(byte[][][] input, byte[][] output, byte[] nonce) {
        SecureRandom KDF;
        for (int i = 0; i < k; i++) {

            BigInteger pkr = this.cs[0].modPow(this.ks[i], this.p);

            this.H.update(pkr.toByteArray());
            this.H.update(ByteBuffer.allocate(4).putInt(s[i]).array());
            this.H.update(nonce);

            // KDF
            byte[] keyFromKDF = new byte[input[0][0].length];
            byte[] seed = this.H.digest();
            KDF = getRndInstance(seed);
//            System.out.println("OTR seed: "+Util.bytesToHex(seed));
            KDF.nextBytes(keyFromKDF);
//            System.out.println("OTR: "+Util.bytesToHex(keyFromKDF));
            output[i] = Util.xor(input[i][s[i]], keyFromKDF);
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
