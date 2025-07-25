package dev.dotfox.bls.impl.blst.g2;

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
        // For MINIMAL_PK scheme, PK is in G1
        P1 pk = new P1(secretKey);
        return new BlstPublicKey(pk.to_affine());
    }

    @Override
    public BlstSignature sign(byte[] message, String dst) {
        // For MINIMAL_PK scheme, Signature is in G2
        P2 p2 = new P2();
        p2.hash_to(message, dst, new byte[0]).sign_with(this.getKey());
        return new BlstSignature(p2.to_affine());
    }
}
