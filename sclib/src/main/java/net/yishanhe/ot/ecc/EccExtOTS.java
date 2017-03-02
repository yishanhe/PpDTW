package net.yishanhe.ot.ecc;

import net.yishanhe.ot.BitMatrix;
import net.yishanhe.ot.ExtOTS;
import net.yishanhe.ot.Util;

import org.spongycastle.jce.spec.ECParameterSpec;
import org.spongycastle.math.ec.ECPoint;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * Created by syi on 7/16/16.
 */
public class EccExtOTS implements ExtOTS<ECPoint> {

    // OT{m,l} m pairs (xj0, xj1) of l bit strings, 0<=j<=m-1
    private int m; // m pairs
    private int l; // l-bit strings.
    private int k; // security parameter, number of pairs of the seed.
    private byte[][][] xs;

    private SecureRandom rnd;

    // parameters for BaseOTR
    private EccBaseOTR baseOTR;
    private byte[] s; // seed selection bit, generated randomly.
    private int sLeadingZeros;
    private SecureRandom[] seededRnd;
    private byte[][] seeds;
    private BitMatrix Q;
    private byte[][][] garbledQ;
    private OTCipher otCipher;

    public EccExtOTS(ECParameterSpec spec, int k, int m, int l) {
        this.k = k;
        this.m = m;
        this.l = l;
        this.rnd = new SecureRandom();
        this.xs = new byte[m][2][Util.getByteLen(l)];
        // generate s for BaseOTR
        this.s = new byte[Util.getByteLen(k)];
        this.sLeadingZeros = Util.getLeadingZeros(k);
        rnd.nextBytes(s);
        this.baseOTR = new EccBaseOTR(spec, k, k, s);

        // init
        this.seeds = new byte[k][Util.getByteLen(k)];
        this.seededRnd = new SecureRandom[k];
        this.Q = new BitMatrix(m, k);
        this.garbledQ = new byte[m][2][Util.getByteLen(l)];
        this.otCipher = new OTCipher();
    }

    public void setXs() {
        SecureRandom rnd = new SecureRandom();
        for (int i = 0; i < m; i++) {
            rnd.nextBytes(this.xs[i][0]);
            rnd.nextBytes(this.xs[i][1]);
        }
    }

    public void setXs(byte[][][] injectedXs) {
        for (int i = 0; i < m; i++) {
            System.arraycopy(injectedXs[i][0], 0, xs[i][0], 0, Util.getByteLen(l));
            System.arraycopy(injectedXs[i][1], 0, xs[i][1], 0, Util.getByteLen(l));
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

    @Override
    public void onReceiveCs(ECPoint[] cs) {
        baseOTR.onReceiveCs(cs);
    }

    @Override
    public ECPoint[] sendPK0s() {
        return baseOTR.sendPK0s();
    }

    @Override
    public void onReceiveSeeds(ECPoint[] grs, byte[][][] garbledSeeds) {
        baseOTR.onReceiveEncrypted(grs, garbledSeeds, seeds, k);
        // fill the seededRnd
        for (int i = 0; i < k; i++) {
            this.seededRnd[i] = this.getRndInstance(seeds[i]);
        }
    }

    @Override
    public void onReceiveUs(byte[][] us) {
        // store Q in the bit matrix
        for (int i = 0; i < k; i++) {
            SecureRandom rnd = this.seededRnd[i];
            byte[] rndBuffer = new byte[Util.getByteLen(m)]; // G(k_i^0)
            rnd.nextBytes(rndBuffer);
            // G(k_i^1) xor G(k_i^0) xor r(selection bit) (all m bits.)
            if (Util.getBit(i, this.sLeadingZeros, this.s)) {
                // 1
                // G(k_i^0) xor (G(k_i^0) xor G(k_i^1) xor r) = G(k_i^1) xor r
                us[i] = Util.xor(us[i], rndBuffer);
            } else {
                // 0
                us[i] =rndBuffer; // (G(k_i^0)
            }
            Q.setColumn(i, us[i]);
        }

        // TODO: run in-place transpose here.
        // generate Q = Q.
        byte[] qj = new byte[Util.getByteLen(k)];
        byte[] qjXorS = new byte[Util.getByteLen(k)];
        for (int j = 0; j < m; j++) {

            Q.getRow(j, qj);
            Q.getRow(j, qjXorS);
            qjXorS = Util.xor(qjXorS, s); // k bytes.

            garbledQ[j][0] = otCipher.encrypt(0, qj,
                    xs[j][0], l);

            garbledQ[j][1] = otCipher.encrypt(1, qjXorS,
                    xs[j][1], l);
        }
    }

    @Override
    public byte[][][] sendGarbledQ() {
        return garbledQ;
    }

    public byte[][] getSeeds() {
        return seeds;
    }

    public byte[] getS() {
        return s;
    }

    public int getsLeadingZeros() {
        return sLeadingZeros;
    }

    public byte[][][] getXs() {
        return xs;
    }
}
