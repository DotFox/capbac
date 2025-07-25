package dev.dotfox.bls;

import dev.dotfox.bls.impl.BLS12381;
import dev.dotfox.bls.impl.BlsException;
import dev.dotfox.bls.impl.PublicKey;
import dev.dotfox.bls.impl.SecretKey;
import dev.dotfox.bls.impl.Signature;
import dev.dotfox.bls.impl.blst.BlstLoader;
import dev.dotfox.bls.impl.blst.g1.BlstPublicKey;
import dev.dotfox.bls.impl.blst.g1.BlstSecretKey;
import dev.dotfox.bls.impl.blst.g1.BlstSignature;

public final class MinSIG extends AbstractBLS {

    private static final BLS12381 impl = BlstLoader.INSTANCE_G1
            .orElseThrow(() -> new BlsException("Failed to load BLST G1 library implementation."));
    public static final MinSIG INSTANCE = new MinSIG();

    private MinSIG() {
    }

    @Override
    protected BLS12381 getImplementation() {
        return impl;
    }

    @Override
    protected int getPublicKeySize() {
        return 96;
    }

    @Override
    protected int getSignatureSize() {
        return 48;
    }

    @Override
    protected String getSchemeName() {
        return "MINIMAL_SIG scheme";
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
