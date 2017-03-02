package net.yishanhe.ot.ecc;

import net.yishanhe.ot.BitMatrix;
import net.yishanhe.ot.ExtOTR;
import net.yishanhe.ot.Util;

import org.spongycastle.jce.spec.ECParameterSpec;
import org.spongycastle.math.ec.ECPoint;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.logging.ConsoleHandler;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Created by syi on 7/16/16.
 */
public class EccExtOTR implements ExtOTR <ECPoint> {

    private static final Logger logger = Logger.getLogger(EccExtOTR.class.getName());
    private int k; // security strength
    private int kLeadingZeros;
    private int m; // m selection bit
    private byte[] r; // selection bit
    private int l;
    private int rLeadingZeros;
    private OTCipher otCipher;
//    private Random rnd;
    private SecureRandom[][] seededRnd;// TODO: explain why need tow dimensions.

    private EccBaseOTS baseOTS;

    private BitMatrix T;
    private byte[][] us; // u^i = t^i xor G(k_i^1) xor r
    private byte[][][] seeds;
    private byte[][][] garbledSeeds;
    private byte[][] xs;


    public EccExtOTR(ECParameterSpec spec, int k, int m, int l) {

        ConsoleHandler ch = new ConsoleHandler();
        ch.setLevel(Level.FINE);
        logger.addHandler(ch);
        logger.setLevel(Level.FINE);

        this.m = m;
        this.k = k;
        this.l = l;
        this.rLeadingZeros = Util.getLeadingZeros(m);
        this.r = new byte[Util.getByteLen(m)];
        this.otCipher = new OTCipher();

        this.seededRnd = new SecureRandom[k][2];
        prepare(); // must be called, before instantiate the baseOTS

        this.baseOTS = new EccBaseOTS(spec,k, k); // m is msg length of base OT.
        this.us = new byte[k][Util.getByteLen(m)];
        this.xs = new byte[m][Util.getByteLen(l)];
    }

    public void setR() {
        SecureRandom rnd = new SecureRandom();
        rnd.nextBytes(this.r);
    }

    public void setR(byte[] injectedR) {
        if (injectedR.length!= Util.getByteLen(m)) {
            throw new IllegalArgumentException("selection bit len not match.");
        }
        System.arraycopy(injectedR, 0, this.r, 0, Util.getByteLen(m));
    }

    @Override
    public void prepare() {
        // init seeds
        this.seeds = new byte[k][2][Util.getByteLen(k)];
        this.garbledSeeds = new byte[k][2][Util.getByteLen(k)];
        SecureRandom seedGenRnd = new SecureRandom();
        for (int i = 0; i < k; i++) {
            seedGenRnd.nextBytes(this.seeds[i][0]);
            this.seededRnd[i][0] = getRndInstance(this.seeds[i][0]);
            seedGenRnd.nextBytes(this.seeds[i][1]);
            this.seededRnd[i][1] = getRndInstance(this.seeds[i][1]);
        }

        // init T, random matrix.
        this.T = new BitMatrix(m, k);
        for (int i = 0; i < k; i++) {
            byte[] ti = new byte[Util.getByteLen(m)]; // ti  (t^i, r xor t^i)
            this.seededRnd[i][0].nextBytes(ti); // the rnd state move one step forward.
            this.T.setColumn(i, ti); // t^i = G(k_i^0)
        }
        logger.finest("T Matrix at extOTR:\n" + T.toString());
    }

    @Override
    public ECPoint[] sendCs() {
        return baseOTS.sendCs();
    }

    @Override
    public ECPoint[] sendGRs() {
        return baseOTS.sendGRs();
    }

    @Override
    public void onReceivePK0s(ECPoint[] PK0s) {
        // shadow seeds, are seeds has been mixed the choices of Receiver using crypto.
        this.baseOTS.onReceivePK0s(PK0s, seeds, garbledSeeds);
    }

    @Override
    public byte[][][] sendSeeds() {
        return garbledSeeds;
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
    public byte[][] sendUs() {
        // copy T into this U
        for (int i = 0; i < k; i++) {
            this.T.getColumn(i, us[i]);
            logger.finest(i+"th column in T, i.e., G(k_i^0): " + Util.byteArrayToBinaryString(us[i]));
            SecureRandom rnd = this.seededRnd[i][1];
            byte[] rndBuffer = new byte[Util.getByteLen(m)];
            rnd.nextBytes(rndBuffer); // G(k_i^1)
            // xor into
            // us k*m us[i] m bits
            // rndBuffer
            //
            this.us[i]= Util.xor(this.us[i], rndBuffer); // G(k_i^1) xor G(k_i^0)
            logger.finest(i+"th G(k_i^1) xor G(k_i^0): " + Util.byteArrayToBinaryString(us[i]));
            this.us[i] = Util.xor(this.us[i], this.r); // G(k_i^1) xor G(k_i^0) xor r(selection bit) (all m bits.)
            logger.finest(i+"th G(k_i^1) xor G(k_i^0) xor r: " + Util.byteArrayToBinaryString(us[i]));
        }
        return this.us;
    }

    @Override
    public void onReceiveQ(byte[][][] garbledQ) {
        // Q new byte[m][2][Util.getByteLen(l)];
        byte[] tj = new byte[Util.getByteLen(k)]; // column byte len.
        logger.finest("Check T before generating Q\n" + T.toString());
        for (int j = 0; j < m; j++) {
//            logger.finest(j+"th row in T: "+Util.byteArrayToBinaryString(tj));
            T.getRow(j, tj);
//            System.out.print(T.toString());
            // tj is k bits
            // while garbledQ[j][1] is l bits.
            logger.finest(j+"th row in T: "+Util.byteArrayToBinaryString(tj));
            if (Util.getBit(j, Util.getLeadingZeros(m), r)) {
                // 1
                this.xs[j] = otCipher.decrypt(1, tj,
                        garbledQ[j][1], l);
            } else {
                // 0
                this.xs[j] = otCipher.decrypt(0, tj,
                        garbledQ[j][0], l);
            }
        }
    }

    public byte[][][] getSeeds() {
        return seeds;
    }

    public byte[] getR() {
        return r;
    }

    public byte[][] getXs() {
        return xs;
    }
}
