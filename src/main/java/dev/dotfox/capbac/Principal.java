package dev.dotfox.capbac;

import dev.dotfox.bls.BLS;
import dev.dotfox.bls.BLSKeyPair;
import dev.dotfox.bls.BLSSecretKey;
import dev.dotfox.bls.BLSSignature;

public class Principal {
    private final PrincipalId id;
    private final BLSSecretKey secretKey;
    private final BLS bls;

    public Principal(CapBACScheme scheme) {
        this.bls = scheme.getBls();
        BLSKeyPair keyPair = this.bls.keyGen();
        this.id = new PrincipalId(keyPair.getPk().toBytes());
        this.secretKey = keyPair.getSk();
    }

    public Principal(BLS bls, BLSKeyPair keyPair) {
        this.bls = bls;
        this.id = new PrincipalId(keyPair.getPk().toBytes());
        this.secretKey = keyPair.getSk();
    }

    public PrincipalId getId() {
        return id;
    }

    public BLSSignature sign(byte[] message) {
        return bls.sign(secretKey, message);
    }
}
