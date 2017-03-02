package net.yishanhe.ot;

/**
 * Created by syi on 7/15/16.
 * baseOT interfaces are designed to let the outlier class can control the input and output
 */
public interface BaseOTS <E>{

    public void prepare();

    public E[] sendCs();

    public E[] sendGRs();

    public void onReceivePK0s(E[] PK0s, byte[][][] input, byte[][][] output);

}
