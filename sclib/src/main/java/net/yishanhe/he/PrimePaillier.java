package net.yishanhe.he;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

import javax.sound.midi.SysexMessage;

/**
 * Created by syi on 4/23/16.
 * reworked.
 *
 * @author syi
 * @version 1.0
 */
public class PrimePaillier implements HeCipher {

    private static boolean isSimpleG = true;
    private static boolean isSimpleR = false;
//    private static boolean isSecureRnd = false;

//    Random rnd;
    private int keySize; // key size, the secure parameter
    private KeyPair keyPair;

    // crypto parameters

    // private key
    private BigInteger lambda; // lambda = lcm(p-1,q-1)
    private BigInteger mu; // L function, modInverse: (L(g^lambda mod n^2 ))^-1 mod n, L(u) = (u-1)/n

    // public key
    private BigInteger n; // modulo n
    private BigInteger nSquare; // squared modulo n*n
    private BigInteger g; // generator


    public PrimePaillier(int keySize, int primeCertainty) {
        this.keySize = keySize;
//        if (isSecureRnd) {
//            rnd = new SecureRandom();
//        } else {
//            rnd = new Random();
//        }
        // generate keys.
        keyGen(keySize, primeCertainty);
    }

    public PrimePaillier(PrimePaillier.PublicKey publicKey ) {
        // PublicKey(n,nSquare,g)
        this.n = publicKey.getN();
        this.nSquare = publicKey.getNSquare();
        this.g = publicKey.getG();
        this.keySize = publicKey.getKeySize();
        this.keyPair = new KeyPair(publicKey, null);
    }

    public PrimePaillier(PrimePaillier.PublicKey publicKey, PrimePaillier.PrivateKey privateKey) {
        this.n = publicKey.getN();
        this.nSquare = publicKey.getNSquare();
        this.g = publicKey.getG();
        this.keySize = publicKey.getKeySize();
        this.mu = privateKey.getMu();
        this.lambda = privateKey.getLambda();
        this.keyPair = new KeyPair(publicKey, privateKey);
    }

    public void keyGen(int keySize, int primeCertainty) {
        BigInteger p = new BigInteger(keySize/2, primeCertainty, new Random());
        BigInteger q = new BigInteger(keySize/2, primeCertainty, new Random());

        // check, and regen p,q if possible
        while (p.equals(q)) {
            q = new BigInteger(keySize/2, primeCertainty, new Random());
        }

        BigInteger pSubOne = p.subtract(BigInteger.ONE);
        BigInteger qSubOne = q.subtract(BigInteger.ONE);

        n = p.multiply(q);
        nSquare = n.multiply(n);

        // next try to get other parameters
        if (isSimpleG) {
            lambda = pSubOne.multiply(qSubOne);
            g = n.add(BigInteger.ONE);
            mu = lambda.modInverse(n);
        } else {
            BigInteger L;
            // lambda = lcm(p-1,q-1) = (p-1)(q-1)/gcd(p-1,q-1)
            lambda = pSubOne.multiply(qSubOne).divide(pSubOne.gcd(qSubOne));

            // get a qualified g
            // @see <a href="http://crypto.stackexchange.com/questions/15571/how-to-select-g-in-paillier-cryptosystem">How to select g?</a>
            do {
                g = new BigInteger(keySize, new Random());
                L = g.modPow(lambda, nSquare).subtract(BigInteger.ONE).divide(n);
            } while (!L.gcd(n).equals(BigInteger.ONE) || !g.gcd(nSquare).equals(BigInteger.ONE));
            // Z^*_n^2 means a set of integer smaller than n^2, relatively prime to n^2, gcd(g,n^2)=1
            // require g in Z^*_n^2 not (Z^*_n)^2
            // (Z^*_n)^2 means a set of pairs (a,b), where a,b are from Z^*_n
            mu = L.modInverse(n);
        }

        keyPair = new KeyPair(new PublicKey(n,nSquare,g, keySize), new PrivateKey(lambda,mu));

    }

    public int getKeySize() {
        return keySize;
    }

    public KeyPair getKeyPair() {
        return keyPair;
    }

    /**
     * the class of publickey
     */
    public class PublicKey {

        private BigInteger n; // modulo n
        private BigInteger nSquare; // modulo n*n
        private BigInteger g; // generator
        private int keySize;

        public PublicKey(BigInteger n, BigInteger nSquare, BigInteger g, int keySize) {
            this.n = n;
            this.nSquare = nSquare;
            this.g = g;
            this.keySize = keySize;
        }

        public BigInteger getN() {
            return n;
        }

        public BigInteger getNSquare() {
            return nSquare;
        }

        public BigInteger getG() {
            return g;
        }

        public int getKeySize() {
            return keySize;
        }
    }


    /**
     * the class of privatekey
     */
    public class PrivateKey {
        private BigInteger lambda; // lambda = lcm(p-1,q-1)
        private BigInteger mu; // precomputed

        public PrivateKey(BigInteger lambda, BigInteger mu) {
            this.lambda = lambda;
            this.mu = mu;
        }

        public BigInteger getLambda() {
            return lambda;
        }

        public BigInteger getMu() {
            return mu;
        }
    }


    /**
     * the class of keypair
     */
    public class KeyPair {
        private PublicKey publicKey;
        private PrivateKey privateKey;

        public KeyPair(PublicKey publicKey, PrivateKey privateKey) {
            this.publicKey = publicKey;
            this.privateKey = privateKey;
        }

        public PublicKey getPublicKey() {
            return publicKey;
        }

        public PrivateKey getPrivateKey() {
            return privateKey;
        }
    }

    /**
     * above are all data structures
     * below are cryptographic operations
     */
    @Override
    public BigInteger encrypt(BigInteger msg) {
        // msg in Z_n
        // r in Z^*_n
        // c =  g^msg . r^n mod n^2
//        System.out.println("g "+g.toString());
//        System.out.println("n "+n.toString());
//        System.out.println("n^2 "+nSquare.toString());
        while (msg.signum()==-1) {
            msg = msg.mod(n);
        }

        if (isSimpleR) {
            return g.modPow(msg,nSquare).multiply((new BigInteger(keySize, new Random())).modPow(n,nSquare)).mod(nSquare);
        } else
            return g.modPow(msg,nSquare).multiply(getRinZnPrime().modPow(n,nSquare)).mod(nSquare);
    }

    @Override
    public BigInteger decrypt(BigInteger c) {
        // msg = L(c^lambda mode n^2) . mu mod n
        if (keyPair.getPrivateKey() == null) {
            throw new IllegalArgumentException("No Private Key for Decryption.");
        }
        BigInteger msg = c.modPow(lambda, nSquare).subtract(BigInteger.ONE).divide(n).multiply(mu).mod(n);

        // tackle negative cases.
        if (msg.compareTo(n.divide(BigInteger.valueOf(2)))>0) {
            msg = msg.subtract(n);
        }
//        if (msg.signum() == -1) {
//            // negative`
//            if (msg.compareTo(n.divide(BigInteger.valueOf(2)).negate())==-1) {
//                msg = msg.add(n);
//            }
//        } else if (msg.signum() == 1) {
//            // positive
//            if (msg.compareTo(n.divide(BigInteger.valueOf(2)).negate())==1) {
//                msg = msg.subtract(n);
//            }
//        }
//        msg = msg.mod(n.divide(BigInteger.valueOf(2)));

        return msg;
    }

    /**
     *
     * @param a first addend in ct
     * @param b second addend in ct
     * @return sum in ct
     */
    @Override
    public BigInteger add(BigInteger a, BigInteger b) {
        return a.multiply(b).mod(nSquare);
    }

    @Override
    public BigInteger reRnd(BigInteger a) {
        return add(a, encrypt(BigInteger.ZERO));
    }

    @Override
    public BigInteger subtract(BigInteger a, BigInteger b) {
        return a.multiply(b.modInverse(nSquare)).mod(nSquare);
    }

    @Override
    public BigInteger multiply(BigInteger ct, int pt) {
        return ct.modPow(BigInteger.valueOf(pt), nSquare);
    }

    @Override
    public BigInteger negate(BigInteger a) {
        return multiply(a,-1);
    }

    @Override
    public BigInteger vectorMultiply(BigInteger[] ctVec, int[] ptVec) {
        if (ctVec.length!=ptVec.length) {
            throw new IllegalArgumentException("Vectors to be multiplied should be of same length.");
        }
        BigInteger result = encrypt(BigInteger.ZERO);
        for (int i = 0; i < ctVec.length; i++) {
            result = add(result, multiply(ctVec[i], ptVec[i]));
        }
        return result;
    }



    /**
     * get a random number in Z^*_n group.
     * set of integers coprime to n.
     * @return
     */
    private BigInteger getRinZnPrime() {
        BigInteger r;
        do {
            r = (new BigInteger(keySize, new Random())).mod(n); // this make sure r is in Zn
        } while (!r.gcd(n).equals(BigInteger.ONE)); // co-prime
        return r;
    }

}
