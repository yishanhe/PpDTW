package net.yishanhe.he;

import java.math.BigInteger;

/**
 * Created by syi on 4/23/16.
 * ECC El Gamal.
 */
public class EccElGamal implements HeCipher {


    private BigInteger G;
    private BigInteger a;


    public class PublicKey {

    }

    public class PrivateKey {

    }

    public class KeyPair {
        private PublicKey publicKey;
        private PrivateKey privateKey;

    }



    @Override
    public BigInteger encrypt(BigInteger m) {
        return null;
    }

    @Override
    public BigInteger decrypt(BigInteger c) {
        return null;
    }

    @Override
    public BigInteger add(BigInteger a, BigInteger b) {
        return null;
    }

    @Override
    public BigInteger reRnd(BigInteger a) {
        return null;
    }

    @Override
    public BigInteger subtract(BigInteger a, BigInteger b) {
        return null;
    }

    @Override
    public BigInteger multiply(BigInteger ct, int pt) {
        return null;
    }

    @Override
    public BigInteger negate(BigInteger a) {
        return null;
    }

    @Override
    public BigInteger vectorMultiply(BigInteger[] ctVec, int[] ptVec) {
        return null;
    }
}
