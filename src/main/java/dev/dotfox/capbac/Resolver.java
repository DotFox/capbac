package dev.dotfox.capbac;

import dev.dotfox.bls.BLSPublicKey;

public interface Resolver {
    BLSPublicKey resolve(byte[] id);
}
