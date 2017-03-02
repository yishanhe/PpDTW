package net.yishanhe.benchmark;

import net.yishanhe.he.PrimePaillier;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * Created by syi on 7/29/16.
 */
public class BenchmarkPaillier {

    // this method will benchmark and print out the measurements
    // on Paillier encryption
    // every process is run 100 times for an average.
    public static int REPEATS = 100;

    public static void benchmarking(int key_size) {
        System.out.println("**** key size: "+key_size+" ****");
        long s_time = 0;
        long e_time = 0;

        PrimePaillier cipher = null;
        BigInteger[] pt = new BigInteger[REPEATS];
        BigInteger[] ct = new BigInteger[REPEATS];
        BigInteger[] ct_add = new BigInteger[REPEATS];
        BigInteger[] ct_mul = new BigInteger[REPEATS];
        SecureRandom rnd = new SecureRandom();
        byte[] ptRndBuffer = new byte[4];
        for (int i = 0; i < REPEATS; i++) {
            rnd.nextBytes(ptRndBuffer);
            pt[i] = new BigInteger(ptRndBuffer);
        }

        cipher = new PrimePaillier(key_size,key_size/2);

        s_time = System.currentTimeMillis();
        System.out.println("** enc **");
        for (int i = 0; i < REPEATS; i++) {
            ct[i] = cipher.encrypt(pt[i]);
        }

        e_time = System.currentTimeMillis();
        System.out.println("** enc: " + (e_time-s_time)/1.0/REPEATS + " ms." );

        s_time = e_time;
        System.out.println("** dec **");
        for (int i = 0; i < REPEATS; i++) {
            pt[i] = cipher.decrypt(ct[i]);
        }
        e_time = System.currentTimeMillis();
        System.out.println("** dec: " + (e_time-s_time)/1.0/REPEATS + " ms." );

        s_time = e_time;
        System.out.println("** add **");
        for (int i = 0; i < REPEATS; i++) {
            ct_add[i] = cipher.add(ct[i],ct[i]);
        }
        e_time = System.currentTimeMillis();
        System.out.println("** add: " + (e_time-s_time)/1.0/REPEATS + " ms." );

        s_time = e_time;
        System.out.println("** mul **");
        for (int i = 0; i < REPEATS; i++) {
            ct_mul[i] = cipher.multiply(ct[i],Integer.valueOf(pt[i].toString(10)));
        }
        e_time = System.currentTimeMillis();
        System.out.println("** mul: " + (e_time-s_time)/1.0/REPEATS + " ms." );
    }

    public static void main(String[] args) {

        benchmarking(64);
        benchmarking(128);
        benchmarking(256);
        benchmarking(512);
        benchmarking(1024);
        benchmarking(2048);

    }
}
