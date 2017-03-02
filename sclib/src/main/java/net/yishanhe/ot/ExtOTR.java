package net.yishanhe.ot;

/**
 * Created by syi on 7/16/16.
 */
public interface ExtOTR <E> {

    public void prepare();

    public E[] sendCs();

    // on receive PK0s and the encrypted seed bit matrix.
    public void onReceivePK0s(E[] PK0s);

    public E[] sendGRs();

    public byte[][][] sendSeeds(); // send seed matrix.

    public byte[][] sendUs(); // send matrix T.

    public void onReceiveQ(byte[][][] garbledQ); // received matrix Q.
}
