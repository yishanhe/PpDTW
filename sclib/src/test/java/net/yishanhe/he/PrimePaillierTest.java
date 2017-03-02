package net.yishanhe.he;

import org.junit.Before;
import org.junit.Test;

import java.math.BigInteger;
import java.security.SecureRandom;

import static org.junit.Assert.*;

/**
 * Created by syi on 4/23/16.
 */
public class PrimePaillierTest {

    private PrimePaillier cipher;

    @Before
    public void setUp() throws Exception {
        cipher = new PrimePaillier(512,256); // 512 -> 1024 bit cipher text.
//        System.out.print(cipher.getKeyPair().getPublicKey().getN().toString());
    }

    @Test
    public void cipherPositive() throws Exception {

        BigInteger ct = BigInteger.valueOf(5);
        BigInteger testct = cipher.decrypt(cipher.encrypt(ct));
        System.out.println("ct bits: "+ cipher.encrypt(ct).toByteArray().length*8);
        System.out.println("** enc: "+ct.toString()+" **");
        System.out.println("** dec: "+testct.toString()+" **");
        assertEquals(testct,ct);
    }

    @Test
    public void cipherNegative() throws Exception {

//        BigInteger ct = BigInteger.valueOf(-5);
        BigInteger ct = BigInteger.valueOf(-3054131844L);
        BigInteger testct = cipher.decrypt(cipher.encrypt(ct.add(cipher.getKeyPair().getPublicKey().getN())));
        System.out.println("** enc: "+ct.toString()+" **");
        System.out.println("** dec: "+testct.toString()+" **");
        assertEquals(testct,ct);
    }

    @Test
    public void addPositive1() throws Exception {
        BigInteger add1 = BigInteger.valueOf(5);
        BigInteger add2 = BigInteger.valueOf(5);
        System.out.println("** add: "+add1.toString()+","+add2.toString()+" **");
        BigInteger testadd = cipher.decrypt(cipher.add(cipher.encrypt(add1),cipher.encrypt(add2)));
        System.out.println("** result: "+testadd.toString()+" **");
        assertEquals(testadd, add1.add(add2));
    }

    @Test
    public void addPositive2() throws Exception {
        BigInteger add1 = BigInteger.valueOf(10);
        BigInteger add2 = BigInteger.valueOf(-5);
        System.out.println("** add: "+add1.toString()+","+add2.toString()+" **");
        BigInteger testadd = cipher.decrypt(cipher.add(cipher.encrypt(add1),cipher.encrypt(add2)));
        System.out.println("** result: "+testadd.toString()+" **");
        assertEquals(testadd, add1.add(add2));
    }

    @Test
    public void addNegative1() throws Exception {
        BigInteger add1 = BigInteger.valueOf(-5);
        BigInteger add2 = BigInteger.valueOf(-5);
        System.out.println("** add: "+add1.toString()+","+add2.toString()+" **");
        BigInteger testadd = cipher.decrypt(cipher.add(cipher.encrypt(add1),cipher.encrypt(add2)));
        System.out.println("** result: "+testadd.toString()+" **");
        assertEquals(testadd, add1.add(add2));
    }

    @Test
    public void addNegative2() throws Exception {
        BigInteger add1 = BigInteger.valueOf(-10);
        BigInteger add2 = BigInteger.valueOf(5);
        System.out.println("** add: "+add1.toString()+","+add2.toString()+" **");
        BigInteger testadd = cipher.decrypt(cipher.add(cipher.encrypt(add1),cipher.encrypt(add2)));
        System.out.println("** result: "+testadd.toString()+" **");
        assertEquals(testadd, add1.add(add2));
    }

    @Test
    public void reRnd() throws Exception {
        BigInteger ct = BigInteger.valueOf(-5);
        BigInteger testct = cipher.decrypt(cipher.reRnd(cipher.encrypt(ct)));
        System.out.println("** rernd: "+ct.toString()+" **");
        System.out.println("** dec: "+testct.toString()+" **");
        assertEquals(testct,ct);
    }

    @Test
    public void substract1() throws Exception {
        BigInteger add1 = BigInteger.valueOf(10);
        BigInteger add2 = BigInteger.valueOf(-5);
        System.out.println("** subtract: "+add1.toString()+","+add2.toString()+" **");
        BigInteger testadd = cipher.decrypt(cipher.subtract(cipher.encrypt(add1),cipher.encrypt(add2)));
        System.out.println("** result: "+testadd.toString()+" **");
        assertEquals(testadd, add1.subtract(add2));
    }

    @Test
    public void substract2() throws Exception {
//        BigInteger add1 = BigInteger.valueOf(-10);
//        BigInteger add2 = BigInteger.valueOf(-5);
        BigInteger add1 = new BigInteger(256, new SecureRandom());
        BigInteger add2 = new BigInteger(256, new SecureRandom());
        System.out.println("** subtract: "+add1.toString()+","+add2.toString()+" **");
        BigInteger testadd = cipher.decrypt(cipher.subtract(cipher.encrypt(add1),cipher.encrypt(add2)));
        System.out.println("** result: "+testadd.toString()+" **");
        assertEquals(testadd, add1.subtract(add2));
    }

    @Test
    public void multiply1() throws Exception {
        BigInteger add1 = BigInteger.valueOf(-10);
        int add2 = -5;
        System.out.println("** multiply: "+add1.toString()+","+add2+" **");
        BigInteger testadd = cipher.decrypt(cipher.multiply(cipher.encrypt(add1),add2));
        System.out.println("** result: "+testadd.toString()+" **");
        assertEquals(testadd, add1.multiply(BigInteger.valueOf(add2)));
    }

    @Test
    public void multiply2() throws Exception {
        BigInteger add1 = BigInteger.valueOf(10);
        int add2 = -5;
        System.out.println("** multiply: "+add1.toString()+","+add2+" **");
        BigInteger testadd = cipher.decrypt(cipher.multiply(cipher.encrypt(add1),add2));
        System.out.println("** result: "+testadd.toString()+" **");
        assertEquals(testadd, add1.multiply(BigInteger.valueOf(add2)));
    }

    @Test
    public void negate() throws Exception {
//        BigInteger ct = BigInteger.valueOf(-5);
        BigInteger ct = new BigInteger(256, new SecureRandom());
        BigInteger testct = cipher.decrypt(cipher.negate(cipher.encrypt(ct)));
        System.out.println("** negate: "+ct.toString()+" **");
        System.out.println("** dec: "+testct.toString()+" **");
        assertEquals(testct,ct.negate());
    }
}