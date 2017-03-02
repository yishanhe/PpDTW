package net.yishanhe.ot.ecc;

import net.yishanhe.ot.Util;

import org.junit.Before;
import org.junit.Test;
import org.spongycastle.jce.ECNamedCurveTable;
import org.spongycastle.jce.spec.ECParameterSpec;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.logging.ConsoleHandler;
import java.util.logging.Level;
import java.util.logging.Logger;

import static org.junit.Assert.*;

/**
 * Created by syi on 7/17/16.
 */
public class EccExtOTTest {

    private static final Logger logger = Logger.getLogger(EccExtOTTest.class.getName());


    int k;
    int m;
    int l;
    ECParameterSpec spec;
    EccExtOTR extOTR;
    EccExtOTS extOTS;
    byte[] r;
    int rLeadingZeros;
    SecureRandom rnd;
    byte[][][] allX;

    @Before
    public void setUp() throws Exception {

        ConsoleHandler ch = new ConsoleHandler();
        ch.setLevel(Level.FINEST);
        logger.addHandler(ch);
        logger.setLevel(Level.FINEST);

        spec = ECNamedCurveTable.getParameterSpec("c2pnb163v1");
        k = 80;
        m = 128;
        rnd = new SecureRandom();
        r = new byte[Util.getByteLen(m)];
        rnd.nextBytes(r);
        rLeadingZeros = Util.getLeadingZeros(m);
        l = 160;
        extOTR = new EccExtOTR(spec, k, m, l );
        extOTR.setR(r);
        extOTS = new EccExtOTS(spec, k, m , l);
        extOTS.setXs();
        allX = extOTS.getXs();

    }

    /**
     * The seed matrix is sent from extOTR(baseOTS) - > extOTS(baseOTR)
     * Save the seeds rnd at the extOTR side as the expectedSeeds
     * compare this to the seed received at the extOTS side, called resultSeeds.
     * @throws Exception
     */
    @Test
    public void testOTCorrectness() throws Exception {

        byte[][][] allSeeds = extOTR.getSeeds();
        System.out.println("allSeeds dimensions: "
                + allSeeds.length + "x"
                + allSeeds[0].length + "x"
                + allSeeds[0][0].length);

        // run the OT protocol
        // prepare INPUT

        // extOTR 1 send cs

        // extOTS 1 receive cs
        extOTS.onReceiveCs(extOTR.sendCs());

        // extOTS 2 send pk0s

        // extOTR 2 receive pk0s
        extOTR.onReceivePK0s(extOTS.sendPK0s());

        // extOTR 3 send grs
        // extOTR 4 send garbled seeds

        // extOTS 3 receive grs and garbled seeds
        extOTS.onReceiveSeeds(extOTR.sendGRs(), extOTR.sendSeeds());

        // compare the result.
        byte[] s = extOTS.getS();
        int sLeadingZeros = extOTS.getsLeadingZeros();

        // generate expected selected seeds
        byte[][] expectedSelectedSeeds = new byte[k][Util.getByteLen(k)];

        System.out.println("expectedSelectedSeeds dimensions: "
                + expectedSelectedSeeds.length + "x"
                + expectedSelectedSeeds[0].length);

        for (int i = 0; i < k; i++) {
            if (Util.getBit(i,sLeadingZeros,s)) {
                // 1
                expectedSelectedSeeds[i] = allSeeds[i][1];
            } else {
                // 0
                expectedSelectedSeeds[i] = allSeeds[i][0];
            }
        }

        // result seeds
        byte[][] resultSelectedSeeds = extOTS.getSeeds();
        System.out.println("resultSelectedSeeds dimensions: "
                + resultSelectedSeeds.length + "x"
                + resultSelectedSeeds[0].length);

        assertArrayEquals(expectedSelectedSeeds, resultSelectedSeeds);

        // extOTR 5 send us
        // extOTS 4 receive us
        extOTS.onReceiveUs(extOTR.sendUs());


        // extOTS 4 send garbled Q.
        // extOTR 5 receive the garbled Q.
        extOTR.onReceiveQ(extOTS.sendGarbledQ());

        // verify result here
        byte[][] resultXs = extOTR.getXs();

        byte[][] expectedSelectedXs = new byte[m][Util.getByteLen(l)];
        for (int i = 0; i < m; i++) {

            if (Util.getBit(i, rLeadingZeros, r)){
                // 1
                expectedSelectedXs[i] = allX[i][1];
            } else {
                // 0
                expectedSelectedXs[i] = allX[i][0];
            }
            logger.finest(i+"th expected:"+Util.byteArrayToBinaryString(expectedSelectedXs[i])+" vs result:"+Util.byteArrayToBinaryString(resultXs[i]));
        }

        assertArrayEquals(expectedSelectedXs, resultXs);
    }

}