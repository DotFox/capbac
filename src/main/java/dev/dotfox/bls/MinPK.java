package dev.dotfox.bls;

import dev.dotfox.bls.impl.BLS12381;
import dev.dotfox.bls.impl.BlsException;
import dev.dotfox.bls.impl.PublicKey;
import dev.dotfox.bls.impl.SecretKey;
import dev.dotfox.bls.impl.Signature;
import dev.dotfox.bls.impl.blst.BlstLoader;
import dev.dotfox.bls.impl.blst.g2.BlstPublicKey;
import dev.dotfox.bls.impl.blst.g2.BlstSecretKey;
import dev.dotfox.bls.impl.blst.g2.BlstSignature;

public final class MinPK extends AbstractBLS {

    private static final BLS12381 impl = BlstLoader.INSTANCE_G2
            .orElseThrow(() -> new BlsException("Failed to load BLST G2 library implementation."));
    public static final MinPK INSTANCE = new MinPK();

    private MinPK() {
    }

    @Override
    protected BLS12381 getImplementation() {
        return impl;
    }

    @Override
    protected int getPublicKeySize() {
        return 48;
    }

    @Override
    protected int getSignatureSize() {
        return 96;
    }

    @Override
    protected String getSchemeName() {
        return "MINIMAL_PK scheme";
    }

    @Override
    protected PublicKey createPublicKey(byte[] payload) {
        return new BlstPublicKey(payload);
    }

    @Override
    protected SecretKey createSecretKey(byte[] payload) {
        return new BlstSecretKey(payload);
    }

    @Override
    protected Signature createSignature(byte[] payload) {
        return new BlstSignature(payload);
    }
}
