package dev.dotfox.capbac;

public interface TrustChecker {
    boolean check(byte[] id);
}
