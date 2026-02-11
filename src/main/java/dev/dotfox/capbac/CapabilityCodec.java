package dev.dotfox.capbac;

import java.io.IOException;

/**
 * A functional interface for decoding a Capability from a byte array.
 *
 * @param <T> The type of Capability to decode to.
 */
@FunctionalInterface
public interface CapabilityCodec<T extends Capability> {
    /**
     * Decodes a byte array into a Capability object.
     *
     * @param bytes The byte array to decode.
     * @return An object of type T representing the capability.
     * @throws IOException if the byte array is malformed or cannot be decoded.
     */
    T fromBytes(byte[] bytes) throws IOException;
}
