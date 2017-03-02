package net.yishanhe.ot.prime;

import net.yishanhe.ot.Util;

import org.junit.Before;
import org.junit.Test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.DSAPublicKey;

import static org.junit.Assert.*;

/**
 * Created by syi on 7/22/16.
 */
public class PrimeNOTTest {

    int k;
    int N;
    KeyPairGenerator keyPairGenerator = null;

    BigInteger p;
    BigInteger q;
    BigInteger g;

    int[] s;

    @Before
    public void setUp() throws Exception {

        try{
            keyPairGenerator = KeyPairGenerator.getInstance("DSA");
        } catch (NoSuchAlgorithmException e){
            e.printStackTrace();
        }

        SecureRandom rnd = new SecureRandom();
        if (keyPairGenerator != null) {
            keyPairGenerator.initialize(512,rnd);
        } else {
            System.out.println("KeyGen failed.");
            return;
        }

        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        DSAPublicKey pub = (DSAPublicKey)keyPair.getPublic();

        p = pub.getParams().getP();
        q = pub.getParams().getG();
        g = pub.getParams().getG();

        k = 100;
        N = 2;

        s = new int[k];
        for (int i = 0; i < k; i++) {
            s[i] = rnd.nextInt(N);
        }
    }

    @Test
    public void testCorrectness() throws Exception {

        PrimeNOTR notr = new PrimeNOTR(p,q,g,k,N);
        PrimeNOTS nots = new PrimeNOTS(p,q,g,k,N);
        nots.prepare();


        int l = 160;
        byte[][][] input = new byte[k][N][Util.getByteLen(l)];
        byte[][][] encrypted = new byte[k][N][Util.getByteLen(l)];
        byte[][] decrypted = new byte[k][Util.getByteLen(l)];

        SecureRandom rnd = new SecureRandom();
        byte[] buffer = new byte[Util.getByteLen(l)]; // set to m/2 to avoid overflow.
        for (int i = 0; i < k; i++) {
            for (int j = 0; j < N; j++) {
                rnd.nextBytes(buffer);
                System.arraycopy(buffer, 0, input[i][j], 0, buffer.length);
            }
        }
        long start1 = System.nanoTime();
        notr.onReceiveCs(nots.sendCs());
        notr.init(s);
        // sender generate nonce
        byte[] nonce = new byte[10];
        rnd.nextBytes(nonce);
        nots.onReceivePK0s(notr.sendPK0s(), input, encrypted, nonce);
        System.out.println(Util.printDimensions(encrypted));
        notr.onReceiveEncrypted(encrypted, decrypted, nonce);
        long end1 = System.nanoTime();

        System.out.println(" OT time elapsed: " + ((end1 - start1) / 1000000000.0) + " sec");
        // verify result
        for (int i = 0; i < k; i++) {
            System.out.println(Util.bytesToHex(input[i][s[i]]));
            System.out.println(Util.bytesToHex(decrypted[i]));
            assertArrayEquals(input[i][s[i]], decrypted[i]);
        }

    }

}