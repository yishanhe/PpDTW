package net.yishanhe.he;

import java.math.BigInteger;

/**
 * Created by syi on 7/9/16.
 */
public interface HeCipher {

    // ciphter function
    public BigInteger encrypt(BigInteger m);
    public BigInteger decrypt(BigInteger c);


    // he function
    public BigInteger add(BigInteger a, BigInteger b);
    public BigInteger reRnd(BigInteger a);
    public BigInteger subtract(BigInteger a, BigInteger b);
    public BigInteger multiply(BigInteger ct, int pt);
    public BigInteger negate(BigInteger a);
    public BigInteger vectorMultiply(BigInteger[] ctVec, int[] ptVec);

}
