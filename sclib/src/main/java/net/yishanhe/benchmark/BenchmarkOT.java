package net.yishanhe.benchmark;

import net.yishanhe.ot.Util;
import net.yishanhe.ot.ecc.EccBaseOTR;
import net.yishanhe.ot.ecc.EccBaseOTS;
import net.yishanhe.ot.ecc.EccExtOTR;
import net.yishanhe.ot.ecc.EccExtOTS;
import net.yishanhe.ot.ecc.OTCipher;
import net.yishanhe.ot.prime.PrimeNOTR;
import net.yishanhe.ot.prime.PrimeNOTS;

import org.spongycastle.jce.ECNamedCurveTable;
import org.spongycastle.jce.spec.ECParameterSpec;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.DSAPublicKey;

/**
 * Created by syi on 7/29/16.
 */
public class BenchmarkOT {

    // benchmark 1-out-of-N OT vs eccBaseOT

    public static void main(String[] args) {

        System.out.println("ECC");
        runEccOT(8);
        runEccOT(16);
        runEccOT(32);
        runEccOT(64);
        runEccOT(128);
        runEccOT(256);
        runEccOT(512);
        runEccOT(1024);
        runEccOT(2048);

        System.out.println("ECC ext");
        runEccOTExt(8);
        runEccOTExt(16);
        runEccOTExt(32);
        runEccOTExt(64);
        runEccOTExt(128);
        runEccOTExt(256);
        runEccOTExt(512);
        runEccOTExt(1024);
        runEccOTExt(2048);

        System.out.println("Prime");
        runPrimeOT(8);
        runPrimeOT(16);
        runPrimeOT(32);
        runPrimeOT(64);
        runPrimeOT(128);
        runPrimeOT(256);
        runPrimeOT(512);
        runPrimeOT(1024);
        runPrimeOT(2048);

    }


    public static void runEccOT(int kappa) {

        // timer
        long s_time = 0;
        long e_time = 0;

        // prepare
        int k = kappa;
        int m = kappa;

        byte[][][] input = new byte[k][2][Util.getByteLen(m)]; // inputs for sender
        byte[][][] encrypted = new byte[k][2][Util.getByteLen(m)];
        byte[][] decrypted = new byte[k][Util.getByteLen(m)];

        ECParameterSpec spec = ECNamedCurveTable.getParameterSpec("c2pnb163v1");;
        SecureRandom rnd = new SecureRandom();
        OTCipher OTCipher = new OTCipher();;

        byte[] s = new byte[Util.getByteLen(k)];
        rnd.nextBytes(s);

        // random input of OTS
        byte[] buffer = new byte[Util.getByteLen(m/2)]; // set to m/2 to avoid overflow.
        for (int i = 0; i < k; i++) {
            rnd.nextBytes(buffer);
            input[i][0] = Util.expandByteArray(buffer, m);
            rnd.nextBytes(buffer);
            input[i][1] = Util.expandByteArray(buffer, m);
        }

        // measure time start here
        EccBaseOTR receiver = new EccBaseOTR(spec, k, m , s);
        EccBaseOTS sender = new EccBaseOTS(spec, k, m);
        s_time = System.currentTimeMillis();
        receiver.onReceiveCs(sender.sendCs());
        sender.onReceivePK0s(receiver.sendPK0s(), input, encrypted);
        // sender will send  grs and also send
        receiver.onReceiveEncrypted(sender.sendGRs(), encrypted, decrypted);
        e_time = System.currentTimeMillis();
        System.out.println("** "+kappa+" OT"+kappa+": " + (e_time-s_time)/1.0 + " ms." );

    }

    public static void runPrimeOT(int kappa) {
        // timer
        long s_time = 0;
        long e_time = 0;

        int k = kappa;
        int N = 2;
        int l = kappa;

        KeyPairGenerator keyPairGenerator = null;

        BigInteger p;
        BigInteger q;
        BigInteger g;

        int[] s;

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

        s = new int[k];
        for (int i = 0; i < k; i++) {
            s[i] = rnd.nextInt(N);
        }




        byte[][][] input = new byte[k][N][Util.getByteLen(l)];
        byte[][][] encrypted = new byte[k][N][Util.getByteLen(l)];
        byte[][] decrypted = new byte[k][Util.getByteLen(l)];

        byte[] buffer = new byte[Util.getByteLen(l)]; // set to m/2 to avoid overflow.
        for (int i = 0; i < k; i++) {
            for (int j = 0; j < N; j++) {
                rnd.nextBytes(buffer);
                System.arraycopy(buffer, 0, input[i][j], 0, buffer.length);
            }
        }
        s_time = System.currentTimeMillis();
        PrimeNOTR notr = new PrimeNOTR(p,q,g,k,N);
        PrimeNOTS nots = new PrimeNOTS(p,q,g,k,N);
        nots.prepare();
        notr.onReceiveCs(nots.sendCs());
        notr.init(s);
        // sender generate nonce
        byte[] nonce = new byte[10];
        rnd.nextBytes(nonce);
        nots.onReceivePK0s(notr.sendPK0s(), input, encrypted, nonce);
        System.out.println(Util.printDimensions(encrypted));
        notr.onReceiveEncrypted(encrypted, decrypted, nonce);
        e_time = System.currentTimeMillis();
        System.out.println("** "+kappa+" OT"+kappa+": " + (e_time-s_time)/1.0 + " ms." );
    }

    public static void runEccOTExt(int kappa) {

        // prepare

        int k;
        int m;
        int l;
        ECParameterSpec spec;
        EccExtOTR extOTR;
        EccExtOTS extOTS;
        byte[] r;
        SecureRandom rnd;

        spec = ECNamedCurveTable.getParameterSpec("c2pnb163v1");
        k = 80;
        m = kappa;
        rnd = new SecureRandom();
        r = new byte[Util.getByteLen(m)];
        rnd.nextBytes(r);
        l = kappa;
        extOTR = new EccExtOTR(spec, k, m, l );
        extOTR.setR(r);
        extOTS = new EccExtOTS(spec, k, m , l);
        extOTS.setXs();

        //
        long s_time = System.currentTimeMillis();

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

        // extOTR 5 send us
        // extOTS 4 receive us
        extOTS.onReceiveUs(extOTR.sendUs());


        // extOTS 4 send garbled Q.
        // extOTR 5 receive the garbled Q.
        extOTR.onReceiveQ(extOTS.sendGarbledQ());

        long e_time = System.currentTimeMillis();

        System.out.println("** "+kappa+" OT"+kappa+": " + (e_time-s_time)/1.0 + " ms." );
    }

}
