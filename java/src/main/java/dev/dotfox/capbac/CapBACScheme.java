package dev.dotfox.capbac;

import java.util.Arrays;

import dev.dotfox.bls.BLS;
import dev.dotfox.bls.MinPK;
import dev.dotfox.bls.MinSIG;

public enum CapBACScheme {
    MIN_PK((byte) 0x01, MinPK.INSTANCE, 96),
    MIN_SIG((byte) 0x02, MinSIG.INSTANCE, 48);

    private final byte id;
    private final BLS bls;
    private final int signatureSize;

    CapBACScheme(byte id, BLS bls, int signatureSize) {
        this.id = id;
        this.bls = bls;
        this.signatureSize = signatureSize;
    }

    public byte getId() {
        return id;
    }

    public BLS getBls() {
        return bls;
    }

    public int getSignatureSize() {
        return signatureSize;
    }

    public static CapBACScheme fromId(byte id) {
        return Arrays.stream(values())
                .filter(scheme -> scheme.id == id)
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Unknown scheme ID: " + id));
    }
}
