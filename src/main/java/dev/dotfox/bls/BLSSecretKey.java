package dev.dotfox.bls;

import dev.dotfox.bls.impl.ByteCodec;
import dev.dotfox.bls.impl.SecretKey;

public class BLSSecretKey implements ByteCodec {
    private final SecretKey sk;

    public SecretKey getSk() {
        return sk;
    }

    public BLSSecretKey(SecretKey sk) {
        this.sk = sk;
    }

    @Override
    public byte[] toBytes() {
        return sk.toBytes();
    }
}
