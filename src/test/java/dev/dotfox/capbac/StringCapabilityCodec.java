package dev.dotfox.capbac;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

public class StringCapabilityCodec implements CapabilityCodec<StringCapability> {
    @Override
    public StringCapability fromBytes(byte[] bytes) throws IOException {
        if (bytes == null) {
            throw new IOException("Cannot decode null bytes into a StringCapability");
        }
        return new StringCapability(new String(bytes, StandardCharsets.UTF_8));
    }
}
