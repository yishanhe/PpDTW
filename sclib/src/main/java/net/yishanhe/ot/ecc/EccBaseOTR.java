package net.yishanhe.ot.ecc;

import net.yishanhe.ot.BaseOTR;
import net.yishanhe.ot.Util;

import org.spongycastle.jce.spec.ECParameterSpec;
import org.spongycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * Created by syi on 7/16/16.
 */
public class EccBaseOTR implements BaseOTR<ECPoint> {

    private ECPoint G;
    private BigInteger order;
    private int k; // number of OT, same as the length of selection bits.
    private BigInteger[] ks; // k, the random k
    private int m; // otCipher text bit length.
    private ECPoint[] PK0s;
    private int sLeadingZeros = 0;
    private SecureRandom rnd;
    private OTCipher otCipher;
    private byte[] s; // selection string, input of receiver.

    public EccBaseOTR(ECParameterSpec spec, int k, int m, byte[] s) {
        this.G = spec.getG();
        this.order = spec.getCurve().getOrder();
        this.k = k;
        if (s.length!=Util.getByteLen(k)) {
            throw new IllegalArgumentException("");
        }
        this.sLeadingZeros = Util.getLeadingZeros(k);
        this.m = m;
        // init.
        this.PK0s = new ECPoint[k];
        this.ks = new BigInteger[k];
        this.otCipher = new OTCipher();
        this.rnd = new SecureRandom();
        this.s = s;
        prepare();
    }

    @Override
    public void prepare() {
        for (int i = 0; i < k; i++) {
            do {
                ks[i] = new BigInteger(this.order.bitLength(), rnd);
            } while (ks[i].subtract(this.order).signum() >= 0);
        }
    }

    @Override
    public void onReceiveCs(ECPoint[] cs) {

        for (int i = 0; i < k; i++) {
            // get selection bit
            if (!Util.getBit(i, this.sLeadingZeros, s)) {
                // select 0
                // PK0 = g^k
                PK0s[i] = this.G.multiply(ks[i]);
            } else {
                // select 1
                // PK0 = c/PK1 = c/g^k
                PK0s[i] = this.G.multiply(ks[i]); // g^k
                PK0s[i] = PK0s[i].negate(); // 1/g^k
                PK0s[i] = cs[i].add(PK0s[i]); // c/g^k
            }
        }
    }

    @Override
    public ECPoint[] sendPK0s() {
        return PK0s;
    }

    @Override
    public void onReceiveEncrypted(ECPoint[] grs, byte[][][] input, byte[][] output) {
        for (int i = 0; i < k; i++) {
            // get the decrypt key g^rk = (g^k)^r -> PK0
            ECPoint grk = grs[i].multiply(ks[i]);
            BigInteger grkBI = Util.ecPointToBI(grk);

            // get selection bit and use the corresponding decryption key.
            if (!Util.getBit(i, this.sLeadingZeros, s)) {
                // select 0
                output[i] = otCipher.decrypt(0, grkBI.toByteArray() , input[i][0], m);
            } else {
                // select 1
                output[i] = otCipher.decrypt(1, grkBI.toByteArray() , input[i][1], m);
            }
        }
    }

    public void onReceiveEncrypted(ECPoint[] grs, byte[][][] input, byte[][] output, int ptBitLen) {
        for (int i = 0; i < k; i++) {
            // get the decrypt key g^rk = (g^k)^r -> PK0
            ECPoint grk = grs[i].multiply(ks[i]);
            BigInteger grkBI = Util.ecPointToBI(grk);

            // get selection bit and use the corresponding decryption key.
            if (!Util.getBit(i, this.sLeadingZeros, s)) {
                // select 0
                output[i] = otCipher.dePadding(otCipher.decrypt(0, grkBI.toByteArray() , input[i][0], m), ptBitLen);
            } else {
                // select 1
                output[i] = otCipher.dePadding(otCipher.decrypt(1, grkBI.toByteArray() , input[i][1], m), ptBitLen);
            }
        }
    }
}
