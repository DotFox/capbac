package dev.dotfox.capbac;

import dev.dotfox.bls.BLS;
import dev.dotfox.bls.BLSKeyPair;
import dev.dotfox.bls.BLSSecretKey;
import dev.dotfox.bls.BLSSignature;

public class Principal {
    private final byte[] id;
    private final BLSSecretKey secretKey;
    private final BLS bls;

    public Principal(CapBACScheme scheme) {
        this.bls = scheme.getBls();
        BLSKeyPair keyPair = this.bls.keyGen();
        this.id = keyPair.getPk().toBytes();
        this.secretKey = keyPair.getSk();
    }

    public Principal(BLS bls, BLSKeyPair keyPair) {
        this.bls = bls;
        this.id = keyPair.getPk().toBytes();
        this.secretKey = keyPair.getSk();
    }

    public byte[] getId() {
        return id.clone();
    }

    public BLSSignature sign(byte[] message) {
        return bls.sign(secretKey, message);
    }
}
