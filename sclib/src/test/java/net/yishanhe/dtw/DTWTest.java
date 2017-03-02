package net.yishanhe.dtw;

import net.yishanhe.he.PrimePaillier;
import net.yishanhe.ot.Util;
import net.yishanhe.ot.prime.PrimeNOTR;
import net.yishanhe.ot.prime.PrimeNOTS;

import org.junit.Before;
import org.junit.Test;
import org.spongycastle.util.BigIntegers;

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
public class DTWTest {
    int[] ys;
    int[] xs;
    BigInteger[][] rSums;
    BigInteger[][] otDistMatrix; // distant mixed with r
    DTWClient client;
    DTWServer server;
    PrimeNOTR receiver;
    PrimeNOTS sender;
    int k;
    int N;
    KeyPairGenerator keyPairGenerator = null;
    SecureRandom rnd;
    PrimePaillier cipher;
    StringBuilder dtwIntermediateResult = new StringBuilder();

    @Before
    public void setUp() throws Exception {

//        ys = new int[]{1,2,3,4};
//        xs = new int[]{1,2,3,4};
        xs = new int[]{1,1,2,3,2,0};
        ys = new int[]{0,1,1,2,3,2,1};
        rnd = new SecureRandom();

        rSums = new BigInteger[xs.length][ys.length];
        otDistMatrix = new BigInteger[xs.length][ys.length];

        // fill rSums
        byte[] rbuffer = new byte[4];
        for (int i = 0; i < xs.length; i++) {
            for (int j = 0; j < ys.length; j++) {
                rnd.nextBytes(rbuffer);
//                rSums[i][j] = new BigInteger(1,rbuffer); // 16 bit rnd
                rSums[i][j] = BigInteger.ZERO; // 16 bit rnd
            }
        }

        // fill otDistMatrix
        for (int i = 0; i < xs.length; i++) {
            for (int j = 0; j < ys.length; j++) {
                otDistMatrix[i][j] = rSums[i][j].add(BigInteger.valueOf(-2*xs[i]*ys[j]+ys[j]*ys[j])); // 16 bit rnd
            }
        }

        cipher = new PrimePaillier(512,64);

        server = new DTWServer(ys, cipher);
//        client = new DTWClient(xs, cipher);
        // debug purpose
        client = new DTWClient(xs, cipher.getKeyPair().getPublicKey(), cipher.getKeyPair().getPrivateKey());

        // set up OT
        try{
            keyPairGenerator = KeyPairGenerator.getInstance("DSA");
        } catch (NoSuchAlgorithmException e){
            e.printStackTrace();
        }
        if (keyPairGenerator != null) {
            keyPairGenerator.initialize(512,rnd); // key length is 2*
        } else {
            System.out.println("KeyGen failed.");
            return;
        }

        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        DSAPublicKey pub = (DSAPublicKey)keyPair.getPublic();

        k = 1;
        N = 3;
        receiver = new PrimeNOTR(pub.getParams().getP(), pub.getParams().getQ(), pub.getParams().getG(), k, N);
        // print
        sender = new PrimeNOTS(pub.getParams().getP(), pub.getParams().getQ(), pub.getParams().getG(), k, N);
        // prepare OTs
        sender.prepare();
        receiver.onReceiveCs(sender.sendCs());


    }


    @Test
    public void testDTWCorrectness() throws Exception {
        server.onReceiveOTDistMatrix(otDistMatrix);

        // prepare
        client.onReceiveR(rSums);

        byte[][][] inputBuffer = new byte[k][N][Util.getByteLen(1024)];
        byte[][][] encInputBuffer = new byte[k][N][Util.getByteLen(1024)];
        byte[][] outputBuffer = new byte[k][Util.getByteLen(1024)];
        byte[] nonce = new byte[10];

        // 1-xslen 1-yslen
        for (int i = 1; i < xs.length; i++) {
            for (int j = 1; j < ys.length; j++) {
                // update nonce
                System.out.println(i+", "+j);
                rnd.nextBytes(nonce);

                // client receives triple from server, and generates the input buffer.
                client.onReceiveTriple(server.sendTriple(i,j), i, j, inputBuffer);
                // input buffer is the OT input.

                int[] s = server.onReceiveTripleDiffCT(client.sendTripleDiffCT());

                // run OT here.
                receiver.init(s);
                // expected
                BigInteger otExpected = BigIntegers.fromUnsignedByteArray(inputBuffer[0][s[0]]);
                sender.onReceivePK0s(receiver.sendPK0s(), inputBuffer, encInputBuffer, nonce );
                receiver.onReceiveEncrypted(encInputBuffer, outputBuffer, nonce );
                BigInteger otResult = BigIntegers.fromUnsignedByteArray(outputBuffer[0]);
                // check correctness of this.
                assertEquals(otExpected, otResult);

                // server(receiver) gets the cipher text
                server.onTripleOTResult(outputBuffer,i,j);
                dtwIntermediateResult.append(i+", "+j+": "+cipher.decrypt(new BigInteger(1,outputBuffer[0])).toString()+"\n");
//                dtwIntermediateResult.append(i+", "+j+": "+cipher.decrypt(BigIntegers.fromUnsignedByteArray(outputBuffer[0])).toString()+"\n");
            }
        }

        // get the result.
        // the R from client
        System.out.println("N, N^2, G:");
        System.out.println(cipher.getKeyPair().getPublicKey().getN());
        System.out.println(cipher.getKeyPair().getPublicKey().getNSquare());
        System.out.println(cipher.getKeyPair().getPublicKey().getG());
        System.out.println();
        System.out.println("server side");
        System.out.println(cipher.decrypt(server.cEncDistMatrix.getItem(xs.length-1, ys.length-1)).toString(2));
        System.out.println("client side");
        System.out.println(cipher.decrypt(client.cEncDistMatrix.getItem(xs.length-1, ys.length-1)).toString(2));
        System.out.println("DTW result:" + cipher.decrypt( cipher.add(server.cEncDistMatrix.getItem(xs.length-1, ys.length-1), client.cEncDistMatrix.getItem(xs.length-1, ys.length-1)) ));
        System.out.println("intermediate result");
        System.out.println(dtwIntermediateResult.toString());
//        assertEquals(BigInteger.ZERO, cipher.decrypt( cipher.add(server.cEncDistMatrix.getItem(xs.length-1, ys.length-1), client.cEncDistMatrix.getItem(xs.length-1, ys.length-1))));
        assertEquals(BigInteger.valueOf(2), cipher.decrypt( cipher.add(server.cEncDistMatrix.getItem(xs.length-1, ys.length-1), client.cEncDistMatrix.getItem(xs.length-1, ys.length-1))));


    }
}