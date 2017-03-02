package net.yishanhe.he;

import net.yishanhe.ot.Util;

import org.junit.Before;
import org.junit.Test;
import org.spongycastle.jce.ECNamedCurveTable;
import org.spongycastle.jce.spec.ECParameterSpec;
import org.spongycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.SecureRandom;

import static org.junit.Assert.*;

/**
 * Created by syi on 7/19/16.
 */
public class EccElGamalTest {

    ECParameterSpec spec;
    ECPoint G;
    BigInteger order;
    SecureRandom rnd;
    ECPoint c;

    @Before
    public void setUp() throws Exception {
        spec = ECNamedCurveTable.getParameterSpec("c2pnb163v1");
        G = spec.getG();
        order = spec.getCurve().getOrder();
        rnd = new SecureRandom();
        BigInteger rs = null;
        do {
            rs = new BigInteger(order.bitLength(), rnd);
        } while (rs.subtract(order).signum()>=0);


        // get random C using rs
        c = G.multiply(rs);
        System.out.println(c.getXCoord().getEncoded().length*8);
        System.out.println(Util.ecPointToBI(c).toByteArray().length*8);
    }

    @Test
    public void testElGamal() throws Exception {

    }
}