package net.yishanhe.ot.ecc;

import net.yishanhe.ot.BaseOTS;
import net.yishanhe.ot.Util;

import org.spongycastle.jce.spec.ECParameterSpec;
import org.spongycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.logging.Logger;

/**
 * Created by syi on 7/16/16.
 */
public class EccBaseOTS implements BaseOTS<ECPoint> {

    private static final Logger LOGGER = Logger.getLogger(EccBaseOTS.class.getName());

    private ECPoint G;
    private BigInteger order;
    private SecureRandom rnd;
    private int k;
    private int m;
    private OTCipher otCipher;

    private BigInteger[] rs;
    private ECPoint[] cs;
    private ECPoint[] crs;
    private ECPoint[] grs;
    private byte[] nonce;

    public EccBaseOTS(ECParameterSpec spec, int k, int m) {
        this.G = spec.getG(); // generator
        this.order = spec.getCurve().getOrder();
        this.k = k;
        this.m = m;
        this.otCipher = new OTCipher();
        this.rnd = new SecureRandom();

        this.rs = new BigInteger[k];
        this.cs = new ECPoint[k];
        this.crs = new ECPoint[k];
        this.grs = new ECPoint[k];
        prepare();
    }

    @Override
    public void prepare() {
        for (int i = 0; i < this.k; i++) {
            // use rs as random buffer to generate random C
            do {
                rs[i] = new BigInteger(order.bitLength(), rnd);
            } while (rs[i].subtract(order).signum()>=0);


            // get random C using rs
            cs[i] = G.multiply(rs[i]);

            // after using rs as rnd buffer, update the real rs
            do {
                rs[i] = new BigInteger(order.bitLength(), rnd);
            } while (rs[i].subtract(order).signum()>=0);

            crs[i] = cs[i].multiply(rs[i]);
            grs[i] = G.multiply(rs[i]);
        }
    }

    @Override
    public ECPoint[] sendCs() {
        return cs;
    }

    @Override
    public ECPoint[] sendGRs() {
        return grs;
    }

    @Override
    public void onReceivePK0s(ECPoint[] PK0s, byte[][][] input, byte[][][] output) {
        for (int i = 0; i < k; i++) {
            BigInteger ri = rs[i];
            ECPoint pk0r = PK0s[i].multiply(ri);
            ECPoint pk1r = pk0r.negate(); // EC curve, negate is 1/x
            pk1r = crs[i].add(pk1r); // pk1r = cr/pk0r = (c/pk0)^r

            // encrypt
            // H(pk0r,0), H(pk0r,1)
            BigInteger pk0rBI = Util.ecPointToBI(pk0r);
            BigInteger pk1rBI = Util.ecPointToBI(pk1r);
            output[i][0] = otCipher.encrypt(0, pk0rBI.toByteArray(),
                    input[i][0], m);
            output[i][1] = otCipher.encrypt(1, pk1rBI.toByteArray(),
                    input[i][1], m);


        }
    }

    public void genNonce() {
        this.nonce = new byte[10];
        SecureRandom rnd = new SecureRandom();
        rnd.nextBytes(nonce);
    }

    public byte[] sendNonce() {
        return nonce;
    }

    public void onReceivePK0s(ECPoint[] PK0s, byte[][][] input, byte[][][] output, byte[] nonce) {
        // we know this ot runs in amortized mode.
        // generate nonce and save it

        for (int i = 0; i < k; i++) {
            BigInteger ri = rs[i];
            ECPoint pk0r = PK0s[i].multiply(ri);
            ECPoint pk1r = pk0r.negate(); // EC curve, negate is 1/x
            pk1r = crs[i].add(pk1r); // pk1r = cr/pk0r = (c/pk0)^r

            // encrypt
            // H(pk0r,0), H(pk0r,1)
            BigInteger pk0rBI = Util.ecPointToBI(pk0r);
            BigInteger pk1rBI = Util.ecPointToBI(pk1r);
            output[i][0] = otCipher.encrypt(0, pk0rBI.toByteArray(),
                    input[i][0], m, nonce);
            output[i][1] = otCipher.encrypt(1, pk1rBI.toByteArray(),
                    input[i][1], m, nonce);


        }
    }
}
