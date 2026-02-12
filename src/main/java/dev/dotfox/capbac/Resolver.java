package dev.dotfox.capbac;

import java.util.Optional;

import dev.dotfox.bls.BLSPublicKey;

public interface Resolver {
    Optional<BLSPublicKey> resolve(PrincipalId id);
}
