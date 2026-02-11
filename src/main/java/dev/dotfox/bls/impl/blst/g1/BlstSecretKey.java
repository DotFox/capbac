package dev.dotfox.bls.impl.blst.g1;

import dev.dotfox.bls.impl.blst.AbstractBlstSecretKey;
import supranational.blst.P1;
import supranational.blst.P2;

public class BlstSecretKey extends AbstractBlstSecretKey {

    public BlstSecretKey(supranational.blst.SecretKey secretKey) {
        super(secretKey);
    }

    public BlstSecretKey(byte[] secretKey) {
        super(secretKey);
    }

    @Override
    public BlstPublicKey derivePublicKey() {
        // For MINIMAL_SIG scheme, PK is in G2
        P2 pk = new P2(secretKey);
        return new BlstPublicKey(pk.to_affine());
    }

    @Override
    public BlstSignature sign(byte[] message, String dst) {
        // For MINIMAL_SIG scheme, Signature is in G1
        P1 p1 = new P1();
        p1.hash_to(message, dst, new byte[0]).sign_with(this.getKey());
        return new BlstSignature(p1.to_affine());
    }
}
