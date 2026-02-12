package dev.dotfox.bls.impl.blst;

import java.lang.reflect.InvocationTargetException;
import java.util.Optional;

import dev.dotfox.bls.impl.BLS12381;

public class BlstLoader {
    public static final Optional<BLS12381> INSTANCE_G1 = loadBlstG1();
    public static final Optional<BLS12381> INSTANCE_G2 = loadBlstG2();

    private static Throwable g1LoadFailure;
    private static Throwable g2LoadFailure;

    private static Optional<BLS12381> loadBlstG1() {
        try {
            Class.forName("supranational.blst.blstJNI");

            final Class<?> blstClass = Class.forName("dev.dotfox.bls.impl.blst.g1.BlstBLS12381");
            return Optional.of((BLS12381) blstClass.getDeclaredConstructor().newInstance());
        } catch (final InstantiationException
                | ExceptionInInitializerError
                | InvocationTargetException
                | NoSuchMethodException
                | IllegalAccessException
                | ClassNotFoundException e) {
            g1LoadFailure = e;
            return Optional.empty();
        }
    }

    private static Optional<BLS12381> loadBlstG2() {
        try {
            Class.forName("supranational.blst.blstJNI");

            final Class<?> blstClass = Class.forName("dev.dotfox.bls.impl.blst.g2.BlstBLS12381");
            return Optional.of((BLS12381) blstClass.getDeclaredConstructor().newInstance());
        } catch (final InstantiationException
                | ExceptionInInitializerError
                | InvocationTargetException
                | NoSuchMethodException
                | IllegalAccessException
                | ClassNotFoundException e) {
            g2LoadFailure = e;
            return Optional.empty();
        }
    }

    public static Throwable getG1LoadFailure() {
        return g1LoadFailure;
    }

    public static Throwable getG2LoadFailure() {
        return g2LoadFailure;
    }
}
