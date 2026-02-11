package dev.dotfox.bls.impl;

public interface PublicKey extends ByteCodec {
    boolean isValid();
}
