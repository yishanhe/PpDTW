package net.yishanhe.main;

import net.yishanhe.dist.EccOTDistClient;
import net.yishanhe.dist.EccOTDistServer;
import net.yishanhe.dtw.DTWClient;
import net.yishanhe.dtw.DTWServer;
import net.yishanhe.he.PrimePaillier;
import net.yishanhe.ot.Util;
import net.yishanhe.ot.ecc.EccExtOTR;
import net.yishanhe.ot.ecc.EccExtOTS;
import net.yishanhe.ot.prime.PrimeNOTR;
import net.yishanhe.ot.prime.PrimeNOTS;

import org.spongycastle.jce.ECNamedCurveTable;
import org.spongycastle.jce.spec.ECParameterSpec;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import java.io.File;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.DSAPublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

/**
 * Created by syi on 4/14/17.
 */

public class OneDollarGesture {

    private static final Logger logger = Logger.getLogger(OneDollarGesture.class.getName());

    public static void main(String[] args) {

        System.out.println("** STEP 0 ** Prepare Measurements.");
        // prepare timer and counter for result
        boolean commCost = true;
        long s_time = 0; //ms
        long e_time = 0; //ms
        long client_time = 0;
        long server_time = 0;
        long bytes_to_client = 0;
        long bytes_to_server = 0;


        System.out.println("** STEP 0 ** Prepare Inputs.");
        int numOfBits = 32;
        // Load input from one dollar dataset.
        String gesture1 = "./fast/check01.xml";
//        String gesture2 = "./fast/circle10.xml";
        String gesture2 = "./fast/check04.xml";


        int[] xs = readGesture(gesture1);
        int[] ys = readGesture(gesture2);
        System.out.println("*** INPUT LENGTH *** is " + xs.length + "x" + ys.length);
        int k = 80; // secure parameter for symmetric encryption.
        int l = numOfBits; // input bit length of an integer. default 32.
        int m = xs.length * ys.length * numOfBits;

        System.out.println("** STEP 0 ** Init Crypto Primitives");

        // init 1-out-of-3 OT
        KeyPairGenerator keyPairGenerator = null;
        try{
            keyPairGenerator = KeyPairGenerator.getInstance("DSA");
        } catch (NoSuchAlgorithmException e){
            e.printStackTrace();
        }
        if (keyPairGenerator != null) {
            keyPairGenerator.initialize(512,new SecureRandom()); // key length is 2*
        } else {
            System.out.println("KeyGen failed.");
            return;
        }
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        DSAPublicKey pub = (DSAPublicKey)keyPair.getPublic();
        int dp_k = 1;
        int dp_N = 3;
        PrimeNOTR oneOutOfThreeOTR = new PrimeNOTR(pub.getParams().getP(), pub.getParams().getQ(), pub.getParams().getG(), dp_k, dp_N);
        // print
        PrimeNOTS oneOutOfThreeOTS = new PrimeNOTS(pub.getParams().getP(), pub.getParams().getQ(), pub.getParams().getG(), dp_k, dp_N);
        // prepare OTs
        oneOutOfThreeOTS.prepare();
        oneOutOfThreeOTR.onReceiveCs(oneOutOfThreeOTS.sendCs());

        // init Ecc OT parameters
        ECParameterSpec spec = ECNamedCurveTable.getParameterSpec("c2pnb163v1");

        // init Paillier cipher.
        PrimePaillier cipher = new PrimePaillier(512,64);

        // init DTW data structure
        byte[][][] inputBuffer = new byte[dp_k][dp_N][Util.getByteLen(1024)];
        byte[][][] encInputBuffer = new byte[dp_k][dp_N][Util.getByteLen(1024)];
        byte[][] outputBuffer = new byte[dp_k][Util.getByteLen(1024)];
        byte[] nonce = new byte[10];

        // secure random
        SecureRandom rnd = new SecureRandom();

        System.out.println("** STEP 1 ** Private Euclidean Distance.");
        // run ExtOT to get init dp matrix


        s_time = System.currentTimeMillis();
        server_time = 0;
        client_time = 0;

        EccOTDistServer distServer = new EccOTDistServer(numOfBits);
        distServer.setYs(ys);
        distServer.onReceiveClientRequest(xs.length);

        if (commCost) bytes_to_server += 4;

        EccExtOTR extOTR = new EccExtOTR(spec, k, m, l);
        extOTR.setR(distServer.sendRToOT());

        e_time = System.currentTimeMillis();
        server_time += (e_time-s_time);
        s_time = e_time;

        EccOTDistClient distClient = new EccOTDistClient(numOfBits);
        distClient.onReceiveServerResponse(ys.length);

        if (commCost) bytes_to_client +=4;

        distClient.setXs(xs);
        distClient.setR(); // inject 0 as random number
        EccExtOTS extOTS = new EccExtOTS(spec, k, m, l);
        extOTS.setXs(distClient.sendXsBufferToOT());
        extOTS.onReceiveCs(extOTR.sendCs()); // S client

        e_time = System.currentTimeMillis();
        client_time += (System.currentTimeMillis()-s_time);
        System.out.println("---- client substep measure:"+(System.currentTimeMillis()-s_time));
        s_time = e_time;

        extOTR.onReceivePK0s(extOTS.sendPK0s()); // r server

        e_time = System.currentTimeMillis();
        server_time += (System.currentTimeMillis()-s_time);
        s_time = e_time;

        extOTS.onReceiveSeeds(extOTR.sendGRs(), extOTR.sendSeeds());
        extOTS.onReceiveUs(extOTR.sendUs());

        e_time = System.currentTimeMillis();
        client_time += (System.currentTimeMillis()-s_time);
        System.out.println("---- client substep measure:"+(System.currentTimeMillis()-s_time));
        s_time = e_time;

        extOTR.onReceiveQ(extOTS.sendGarbledQ());


        if (commCost) {
            bytes_to_client += extOTR.sendCs().length*20;
            bytes_to_server += extOTS.sendPK0s().length*20;
            bytes_to_client += extOTR.sendGRs().length*20;
            bytes_to_client += extOTR.sendSeeds().length*extOTR.sendSeeds()[0].length*extOTR.sendSeeds()[0][0].length;
            bytes_to_client += extOTR.sendUs().length*extOTR.sendUs()[0].length;
            bytes_to_server += extOTS.sendGarbledQ().length*extOTS.sendGarbledQ()[0].length*extOTS.sendGarbledQ()[0][0].length;
        }

        // get dp matrix
        distServer.onReceiveXsBufferFromOT(extOTR.getXs());
//        logger.fine("result dp matrix:\n"+Util.printBigIntegerMatrix(distServer.distMatrix));

        e_time = System.currentTimeMillis();
        server_time += (System.currentTimeMillis()-s_time);
        s_time = e_time;

        // print
        System.out.println("** STEP 1 ** Time at Client side: " + client_time/1000.0 + " seconds." );
        System.out.println("** STEP 1 ** Time at Server side: " + server_time/1000.0 + " seconds." );

        // reset timer
        server_time = 0;
        client_time = 0;

        System.out.println("** STEP 2 ** Private Dynamic Programming Matrix Filling.");
        s_time = System.currentTimeMillis();


        DTWServer server = new DTWServer(ys, cipher);
        server.onReceiveOTDistMatrix(distServer.distMatrix); // locally

        e_time = System.currentTimeMillis();
        server_time += (System.currentTimeMillis()-s_time);
        s_time = e_time;


        DTWClient client = new DTWClient(xs, cipher.getKeyPair().getPublicKey(), cipher.getKeyPair().getPrivateKey());
        client.onReceiveR(distClient.getrSums()); // run locally.

        e_time = System.currentTimeMillis();
        client_time += (System.currentTimeMillis()-s_time);
        s_time = e_time;

        for (int i = 1; i < xs.length; i++) {
            for (int j = 1; j < ys.length; j++) {

                rnd.nextBytes(nonce);

                // client receives triple from server, and generates the input buffer.
                client.onReceiveTriple(server.sendTriple(i,j), i, j, inputBuffer);

                e_time = System.currentTimeMillis();
                client_time += (System.currentTimeMillis()-s_time);
                s_time = e_time;

                if (commCost) {
                    bytes_to_client += server.sendTriple(i,j)[0].toByteArray().length + server.sendTriple(i,j)[1].toByteArray().length + server.sendTriple(i,j)[2].toByteArray().length;
                }
                // input buffer is the OT input.

                int[] s = server.onReceiveTripleDiffCT(client.sendTripleDiffCT());
                if (commCost) {
                    bytes_to_server += client.sendTripleDiffCT()[0].toByteArray().length + client.sendTripleDiffCT()[1].toByteArray().length + client.sendTripleDiffCT()[2].toByteArray().length;
                }
                // run OT here.
                oneOutOfThreeOTR.init(s); // r server

                e_time = System.currentTimeMillis();
                server_time += (System.currentTimeMillis()-s_time);
                s_time = e_time;

                // expected
//                BigInteger otExpected = BigIntegers.fromUnsignedByteArray(inputBuffer[0][s[0]]);
                oneOutOfThreeOTS.onReceivePK0s(oneOutOfThreeOTR.sendPK0s(), inputBuffer, encInputBuffer, nonce );
                e_time = System.currentTimeMillis();
                client_time += (System.currentTimeMillis()-s_time);
                s_time = e_time;

                if (commCost) {
                    BigInteger[] tmp = oneOutOfThreeOTR.sendPK0s();
                    for (int ii = 0; ii < tmp.length; ii++) {
                        bytes_to_client += tmp[ii].toByteArray().length;
                    }
                }
                oneOutOfThreeOTR.onReceiveEncrypted(encInputBuffer, outputBuffer, nonce );


                if (commCost) {
                    bytes_to_server += nonce.length;
                    bytes_to_server += dp_k*dp_N*Util.getByteLen(1024);
                }
//                BigInteger otResult = BigIntegers.fromUnsignedByteArray(outputBuffer[0]);

                // server(receiver) gets the cipher text
                server.onTripleOTResult(outputBuffer,i,j); // run locally
                e_time = System.currentTimeMillis();
                server_time += (System.currentTimeMillis()-s_time);
                s_time = e_time;
            }
        }

        // print
        System.out.println("** STEP 2 ** Time at Client side: " + client_time/1000.0 + " seconds." );
        System.out.println("** STEP 2 ** Time at Server side: " + server_time/1000.0 + " seconds." );

        System.out.println(cipher.decrypt( cipher.add(server.cEncDistMatrix.getItem(xs.length-1, ys.length-1), client.cEncDistMatrix.getItem(xs.length-1, ys.length-1))));
        if (commCost) {
            System.out.println(bytes_to_client*8/1024.0/1024.0+" MB");
            System.out.println(bytes_to_server*8/1024.0/1024.0+" MB");
        }
    }


    private static int[] readGesture(String filepath) {
        List<Integer> result = new ArrayList<>();
        try {
            File inputFile = new File(filepath);
            DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
            DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
            Document doc = dBuilder.parse(inputFile);
            doc.getDocumentElement().normalize();
            NodeList nList = doc.getElementsByTagName("Point");
            for (int i = 0; i < nList.getLength(); i++) {
                Node point = nList.item(i);
                result.add(Integer.valueOf(point.getAttributes().item(1).getNodeValue()));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return toIntArray(result);
    }

    private static int[] toIntArray(List<Integer> list)  {
        int[] ret = new int[list.size()];
        int i = 0;
        for (Integer e : list)
            ret[i++] = e;
        return ret;
    }
}
