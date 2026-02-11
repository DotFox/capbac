package dev.dotfox.bls.impl.blst;

import dev.dotfox.bls.impl.PublicKey;
import dev.dotfox.bls.impl.SecretKey;
import dev.dotfox.bls.impl.Signature;

public abstract class AbstractBlstSecretKey implements SecretKey {
    protected final supranational.blst.SecretKey secretKey;

    public AbstractBlstSecretKey(supranational.blst.SecretKey secretKey) {
        this.secretKey = secretKey;
    }

    public AbstractBlstSecretKey(byte[] secretKeyBytes) {
        supranational.blst.SecretKey sk = new supranational.blst.SecretKey();
        sk.from_bendian(secretKeyBytes);
        this.secretKey = sk;
    }

    @Override
    public byte[] toBytes() {
        return secretKey.to_bendian();
    }

    public supranational.blst.SecretKey getKey() {
        return secretKey;
    }

    @Override
    public void destroy() {
        secretKey.from_bendian(new byte[32]);
    }

    @Override
    public abstract PublicKey derivePublicKey();

    @Override
    public abstract Signature sign(byte[] message, String dst);
}
