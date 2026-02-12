package dev.dotfox.capbac;

import java.nio.charset.StandardCharsets;
import java.util.Objects;

public class StringCapability implements Capability {
    private final String value;

    public StringCapability(String value) {
        this.value = Objects.requireNonNull(value, "value must not be null");
    }

    public String getValue() {
        return value;
    }

    @Override
    public byte[] toBytes() {
        return value.getBytes(StandardCharsets.UTF_8);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (o == null || getClass() != o.getClass())
            return false;
        StringCapability that = (StringCapability) o;
        return java.util.Objects.equals(value, that.value);
    }

    @Override
    public int hashCode() {
        return java.util.Objects.hash(value);
    }

    @Override
    public String toString() {
        return "StringCapability{" +
                "value='" + value + '\'' +
                '}';
    }
}
