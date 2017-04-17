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
import org.spongycastle.math.ec.ECPoint;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import java.io.File;
import java.io.FileNotFoundException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.DSAPublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.Scanner;
import java.util.logging.Logger;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

/**
 * Created by syi on 4/14/17.
 */

public class MeasureMain {
    private static final Logger logger = Logger.getLogger(MobilePPGRA.class.getName());

    public static void main(String[] args) {

        String gesture1 = "./fast/circle01.xml";
        Run(gesture1, "./fast/check01.xml" );
        Run(gesture1, "./fast/circle01.xml" );
        Run(gesture1, "./fast/delete_mark01.xml" );
        Run(gesture1, "./fast/pigtail01.xml" );
        Run(gesture1, "./fast/question_mark01.xml" );
        Run(gesture1, "./fast/rectangle01.xml" );
        Run(gesture1, "./fast/triangle02.xml" );
    }

    public static void Run(String gesture1, String gesture2) {
        System.out.println("Input: "+gesture1+", "+gesture2);
        int[] xs = readGesture(gesture1);
        int[] ys = readGesture(gesture2);
        Run(xs, ys);
    }

    private static void Run(int inputLength) {
        int[] xs = generateInput(inputLength);
        int[] ys = generateInput(inputLength);
        Run(xs, ys);
    }

    private static void Run(int[] xs, int[]ys) {
        // set debug level.

        System.out.println("*** INPUT LENGTH *** is " + xs.length + "x" + ys.length);

        System.out.println("** STEP 0 ** Prepare Measurements.");
        // prepare timer and counter for result
        boolean commCost = true;
        long s_time = 0; //ms
        long duration = 0;//ms
        long e_time = 0; //ms
        long client_time = 0;
        long server_time = 0;
        long bytes_step = 0;
        long bytes_to_client = 0;
        long bytes_to_server = 0;


        System.out.println("** STEP 0 ** Prepare Inputs.");
        int numOfBits = 32;
//        int[] xs = new int[]{1,2,3,4};
//        int[] ys = new int[]{1,2,3,4};
        //http://nipunbatra.github.io/2014/07/dtw/
//        int[] xs = new int[]{1,1,2,3,2,0};
//        int[] ys = new int[]{0,1,1,2,3,2,1};
//        int[] xs = loadData("ClientSequence");
//        int[] ys = loadData("ServerSequence");




        int k = 80; // secure parameter for symmetric encryption.
        int l = numOfBits; // input bit length of an integer. default 32.
        int m = xs.length * ys.length * numOfBits;

        System.out.println("** STEP 0 ** Init Crypto Primitives (Time cost can be amortized.)");

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

        // init

        EccOTDistClient distClient = new EccOTDistClient(numOfBits);

        System.out.println("** STEP 1 ** Private Euclidean Distance. (Measurement started.)");


        // run ExtOT to get init dp matrix

        /***************************** server part *********************************/
        s_time = System.currentTimeMillis();

        EccOTDistServer distServer = new EccOTDistServer(numOfBits);
        distServer.setYs(ys);
        distServer.onReceiveClientRequest(xs.length);


        EccExtOTR extOTR = new EccExtOTR(spec, k, m, l); // server is the ExtOTReceiver
        extOTR.setR(distServer.sendRToOT());
        ECPoint[] cs = extOTR.sendCs();

        e_time = System.currentTimeMillis();
        duration = e_time - s_time;
        server_time += duration;
        bytes_to_server += 4; // request

        bytes_step= cs.length*20;
        bytes_to_client += bytes_step;
        System.out.println("** STEP 1 ** Private Euclidean Distance. server --> client: "
                + duration/1000.0 + " seconds. "
                + bytes_step*8/1024.0/1024.0 + " MB.");

        /***************************** client part *********************************/
        s_time = System.currentTimeMillis();;
        distClient.onReceiveServerResponse(ys.length);

        distClient.setXs(xs); // client is the ExtOTSender
        distClient.setR(); // inject 0 as random number
        EccExtOTS extOTS = new EccExtOTS(spec, k, m, l);
        extOTS.setXs(distClient.sendXsBufferToOT());
        extOTS.onReceiveCs(cs); // S client

        ECPoint[] pk0s = extOTS.sendPK0s();
        e_time = System.currentTimeMillis();
        duration = e_time - s_time;
        client_time += duration;
        bytes_to_client +=4; // request response
        bytes_step = pk0s.length*20;
        bytes_to_server += bytes_step;
        System.out.println("** STEP 1 ** Private Euclidean Distance. server <-- client: "
                + duration/1000.0 + " seconds. "
                + bytes_step*8/1024.0/1024.0 + " MB.");

        /***************************** server part *********************************/
        s_time = System.currentTimeMillis();

        extOTR.onReceivePK0s(pk0s); // r server
        ECPoint[] grs = extOTR.sendGRs();
        byte[][][] seeds = extOTR.sendSeeds();
        byte[][] us = extOTR.sendUs();
        e_time = System.currentTimeMillis();
        duration = e_time - s_time;
        server_time += duration;

        bytes_step = grs.length*20;
        bytes_step += seeds.length*seeds[0].length*seeds[0][0].length;
        bytes_step += us.length*us[0].length;
        bytes_to_client += bytes_step;
        System.out.println("** STEP 1 ** Private Euclidean Distance. server --> client: "
                + duration/1000.0 + " seconds. "
                + bytes_step*8/1024.0/1024.0 + " MB.");

        /***************************** client part *********************************/
        s_time = System.currentTimeMillis();

        extOTS.onReceiveSeeds(grs, seeds); // this time cost can be amortized, reusing it with a expiring time.
        extOTS.onReceiveUs(us);
        byte[][][] garbledq = extOTS.sendGarbledQ();

        e_time = System.currentTimeMillis();
        duration = e_time - s_time;
        client_time += duration;
        bytes_step = garbledq.length*garbledq[0].length*garbledq[0][0].length;
        bytes_to_server += bytes_step;
        System.out.println("** STEP 1 ** Private Euclidean Distance. server <-- client: "
                + duration/1000.0 + " seconds. "
                + bytes_step*8/1024.0/1024.0 + " MB.");

        System.out.println("** STEP 1 ** Time at Client side: " + client_time/1000.0 + " seconds." );

        /***************************** server part *********************************/
        s_time = System.currentTimeMillis();


        extOTR.onReceiveQ(garbledq);

        // get dp matrix
        distServer.onReceiveXsBufferFromOT(extOTR.getXs());

        e_time = System.currentTimeMillis();
        duration = e_time - s_time;
        server_time += duration;
        System.out.println("** STEP 1 ** Private Euclidean Distance. server --> server: "
                + duration/1000.0 + " seconds. ");

        // print
        System.out.println("** STEP 1 ** Time at Server side: " + server_time/1000.0 + " seconds." );

        // reset timer
        server_time = 0;
        client_time = 0;

        System.out.println("** STEP 2 ** Private Dynamic Programming Matrix Filling.");

        /***************************** server part *********************************/
        s_time = System.currentTimeMillis();


        DTWServer server = new DTWServer(ys, cipher);
        server.onReceiveOTDistMatrix(distServer.distMatrix); // locally

        e_time = System.currentTimeMillis();
        duration = e_time -s_time;
        server_time += duration;

        System.out.println("** STEP 2 ** Private Dynamic Programming Matrix Filling. server --> server: " + duration/1000.0 + " seconds." );


        /***************************** client part *********************************/
        s_time = System.currentTimeMillis();

        DTWClient client = new DTWClient(xs, cipher.getKeyPair().getPublicKey(), cipher.getKeyPair().getPrivateKey());
        client.onReceiveR(distClient.getrSums()); // run locally.

        e_time = System.currentTimeMillis();
        duration = e_time-s_time;
        client_time += duration;
        System.out.println("** STEP 2 ** Private Dynamic Programming Matrix Filling. server --> server: " + duration/1000.0 + " seconds." );


        /***************************** client/server interactive part *********************************/

        long client_duration = 0;
        long server_duration = 0;

        for (int i = 1; i < xs.length; i++) {
            for (int j = 1; j < ys.length; j++) {

                /* server -> client */
                s_time = System.currentTimeMillis();
                BigInteger[] triple =  server.sendTriple(i,j);
                e_time = System.currentTimeMillis();
                server_duration += (e_time-s_time);
                bytes_to_client += triple[0].toByteArray().length + triple[1].toByteArray().length + triple[2].toByteArray().length;


                /* client -> server */
                // client receives triple from server, and generates the input buffer.
                s_time = System.currentTimeMillis();
                client.onReceiveTriple(triple, i, j, inputBuffer);
                BigInteger[] tripleDiffCT = client.sendTripleDiffCT();
                e_time = System.currentTimeMillis();
                client_duration += (e_time-s_time);

                bytes_to_server += tripleDiffCT[0].toByteArray().length + tripleDiffCT[1].toByteArray().length + tripleDiffCT[2].toByteArray().length;

                /* server -> client */
                s_time = System.currentTimeMillis();
                int[] s = server.onReceiveTripleDiffCT(tripleDiffCT);
                // run OT here.
                oneOutOfThreeOTR.init(s); // r server
                BigInteger[] pk0sTriOT = oneOutOfThreeOTR.sendPK0s();
                e_time = System.currentTimeMillis();
                server_duration += (e_time-s_time);

                for (int ii = 0; ii < pk0sTriOT.length; ii++) {
                    bytes_to_client += pk0sTriOT[ii].toByteArray().length;
                }


                rnd.nextBytes(nonce);

                /* client -> server */
                // expected
                // BigInteger otExpected = BigIntegers.fromUnsignedByteArray(inputBuffer[0][s[0]]);

                s_time = System.currentTimeMillis();
                oneOutOfThreeOTS.onReceivePK0s(pk0sTriOT, inputBuffer, encInputBuffer, nonce );
                e_time = System.currentTimeMillis();
                client_duration += (e_time-s_time);


                /* server -> server */
                s_time = System.currentTimeMillis();
                oneOutOfThreeOTR.onReceiveEncrypted(encInputBuffer, outputBuffer, nonce );
                server.onTripleOTResult(outputBuffer,i,j); // run locally
                e_time = System.currentTimeMillis();
                server_duration += (e_time-s_time);

                bytes_to_server += nonce.length;
                bytes_to_server += dp_k*dp_N*Util.getByteLen(1024);

//                BigInteger otResult = BigIntegers.fromUnsignedByteArray(outputBuffer[0]);

                // server(receiver) gets the cipher text

            }
        }

        // print
        System.out.println("** STEP 2 ** Matrix Filling Loop Time at Client side: " + client_duration/1000.0 + " seconds." );
        System.out.println("** STEP 2 ** Matrix Filling Loop Time at Server side: " + server_duration/1000.0 + " seconds." );
        System.out.println("** STEP 2 ** Time at Client side: " + (client_time+client_duration)/1000.0 + " seconds." );
        System.out.println("** STEP 2 ** Time at Server side: " + (server_time+server_duration)/1000.0 + " seconds." );
        System.out.println("** DTW result: ");
        System.out.println(cipher.decrypt( cipher.add(server.cEncDistMatrix.getItem(xs.length-1, ys.length-1), client.cEncDistMatrix.getItem(xs.length-1, ys.length-1))));
        System.out.println("client data: " + bytes_to_client*8/1024.0/1024.0+" MB");
        System.out.println("server data: " + bytes_to_server*8/1024.0/1024.0+" MB");

    }

    private static int[] loadData(String FILE_NAME){
        ArrayList<Integer> result = new ArrayList<>();
        try {
            Scanner inputFile = new Scanner(new File(FILE_NAME));
            inputFile.useDelimiter(",");
            while (inputFile.hasNext()) {
                String element = inputFile.next();
                result.add(Integer.parseInt(element));
            }
            inputFile.close();
        } catch (FileNotFoundException e) {
            System.out.println("File cannot be found.");
        }
        return buildIntArray(result);
    }

    private static int[] buildIntArray(List<Integer> integers) {
        int[] ints = new int[integers.size()];
        int i = 0;
        for (Integer n : integers) {
            ints[i++] = n;
        }
        return ints;
    }

    private static int[] generateInput(int inputLength) {
        int RANGE = 100;
        Random rnd = new Random();
        int[] result = new int[inputLength];
        for (int i = 0; i < inputLength; i++) {
            result[i] = rnd.nextInt(RANGE);
        }
        return result;
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
