package dev.dotfox.capbac;

import java.util.Arrays;

import dev.dotfox.bls.BLS;
import dev.dotfox.bls.MinPK;
import dev.dotfox.bls.MinSIG;

public enum CapBACScheme {
    MIN_PK((byte) 0x01, MinPK.INSTANCE, 96),
    MIN_SIG((byte) 0x02, MinSIG.INSTANCE, 48),
    MIN_PK_NON_EXPIRING((byte) 0x05, MinPK.INSTANCE, 96),
    MIN_SIG_NON_EXPIRING((byte) 0x06, MinSIG.INSTANCE, 48);

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

    public boolean hasExpiringCerts() {
        return (id & 0x04) == 0;
    }

    public static CapBACScheme fromId(byte id) {
        if ((id & 0xF8) != 0) {
            throw new IllegalArgumentException("Reserved bits set in scheme ID: 0x" + String.format("%02X", id));
        }
        int blsBits = id & 0x03;
        if (blsBits == 0 || blsBits == 3) {
            throw new IllegalArgumentException("Invalid BLS scheme bits in scheme ID: 0x" + String.format("%02X", id));
        }
        return Arrays.stream(values())
                .filter(scheme -> scheme.id == id)
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Unknown scheme ID: 0x" + String.format("%02X", id)));
    }
}
