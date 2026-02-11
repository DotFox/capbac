package dev.dotfox.bls.impl;

public interface SecretKey extends ByteCodec {
    PublicKey derivePublicKey();

    Signature sign(byte[] message, String dst);

    void destroy();
}
