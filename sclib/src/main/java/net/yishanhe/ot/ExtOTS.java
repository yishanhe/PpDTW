package net.yishanhe.ot;

/**
 * Created by syi on 7/16/16.
 */
public interface ExtOTS <E> {



    // receive cs
    public void onReceiveCs(E[]cs);

    // send pk0s
    public E[] sendPK0s();

    // receive grs and encSeedMat
    public void onReceiveSeeds(E[] grs, byte[][][] garbledSeeds) ;

    public void onReceiveUs(byte[][] us); // generate matrix q.

    public byte[][][] sendGarbledQ(); // send garbled bit matrix q


}
