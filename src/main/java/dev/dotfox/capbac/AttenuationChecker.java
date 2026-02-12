package dev.dotfox.capbac;

@FunctionalInterface
public interface AttenuationChecker<T extends Capability> {
    boolean isValidAttenuation(T parent, T child);
}
