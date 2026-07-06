package yentra.core;

/**
 * 128-bit signature key (two longs from a SHA-256 prefix). Compact and effectively
 * collision-free for any realistic HTTP history size.
 */
public final class Signature {
    public final long hi;
    public final long lo;

    public Signature(long hi, long lo) {
        this.hi = hi;
        this.lo = lo;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Signature s)) return false;
        return hi == s.hi && lo == s.lo;
    }

    @Override
    public int hashCode() {
        long x = hi ^ lo;
        return (int) (x ^ (x >>> 32));
    }

    @Override
    public String toString() {
        return String.format("%016x%016x", hi, lo);
    }
}
