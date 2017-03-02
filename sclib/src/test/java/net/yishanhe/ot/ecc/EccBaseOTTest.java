package net.yishanhe.ot.ecc;

import net.yishanhe.ot.Util;

import org.junit.Before;
import org.junit.Test;
import org.spongycastle.jce.ECNamedCurveTable;
import org.spongycastle.jce.spec.ECParameterSpec;

import java.security.SecureRandom;

import static org.junit.Assert.*;

/**
 * Created by syi on 7/16/16.
 */
public class EccBaseOTTest {

    ECParameterSpec spec;
    SecureRandom rnd;
    OTCipher OTCipher;

    @Before
    public void setUp() throws Exception {
        spec = ECNamedCurveTable.getParameterSpec("c2pnb163v1");
        rnd = new SecureRandom();
        OTCipher = new OTCipher();
    }

    @Test
    public void testCorrectness() throws Exception {

        int k = 100;
        int m = 160;

        byte[][][] input = new byte[k][2][m]; // inputs for sender
        byte[][][] encrypted = new byte[k][2][m];
        byte[][] decrypted = new byte[k][m];

        byte[] s = new byte[Util.getByteLen(k)];

        // random selection bit, input of OTR
        rnd.nextBytes(s);

        // random input of OTS
        byte[] buffer = new byte[Util.getByteLen(m/2)]; // set to m/2 to avoid overflow.
        for (int i = 0; i < k; i++) {
            rnd.nextBytes(buffer);
            input[i][0] = Util.expandByteArray(buffer, m);
            rnd.nextBytes(buffer);
            input[i][1] = Util.expandByteArray(buffer, m);
        }

        EccBaseOTR receiver = new EccBaseOTR(spec, k, m , s);
        EccBaseOTS sender = new EccBaseOTS(spec, k, m);

        receiver.onReceiveCs(sender.sendCs());
        sender.onReceivePK0s(receiver.sendPK0s(), input, encrypted);
        // sender will send  grs and also send
        receiver.onReceiveEncrypted(sender.sendGRs(), encrypted, decrypted);

        // verify result
        for (int i = 0; i < k; i++) {
            if (!Util.getBit(i, Util.getLeadingZeros(k), s)) {
                assertArrayEquals(input[i][0], decrypted[i]);
            } else {
                assertArrayEquals(input[i][1], decrypted[i]);
            }
        }
    }
}