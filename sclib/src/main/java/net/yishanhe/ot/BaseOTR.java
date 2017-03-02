package net.yishanhe.ot;

import java.util.Random;

/**
 * Created by syi on 7/15/16.
 * baseOT interfaces are designed to let the outlier class can control the input and output
 */
public interface BaseOTR <E> {
    public void prepare();
    // receive Cs and get Pks.
    public void onReceiveCs(E[]cs);

    public E[] sendPK0s();

    // receive cipher texts
    public void onReceiveEncrypted(E[] grs, byte[][][] encMat, byte[][] decMat) ;
}