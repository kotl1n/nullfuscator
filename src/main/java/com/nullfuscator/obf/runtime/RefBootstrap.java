package com.nullfuscator.obf.runtime;

import java.lang.invoke.CallSite;
import java.lang.invoke.ConstantCallSite;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;

public final class RefBootstrap {

    private RefBootstrap() {}

    private static final char SEP = 1;
    public static CallSite bootstrap(MethodHandles.Lookup caller, String name,
                                     MethodType type, String enc, int keyA, int keyB,
                                     int mul, int add, int nonce) throws Throwable {
        String callerName = caller.lookupClass().getName().replace('.', '/');
        int key = mix(keyA, keyB, name.hashCode(), callerName.hashCode(),
                type.toMethodDescriptorString().hashCode(), nonce);
        String dec = crypt(enc, key, mul, add, nonce);
        char kind = dec.charAt(0);
        int p1 = dec.indexOf(SEP, 1);
        int p2 = dec.indexOf(SEP, p1 + 1);
        String owner = dec.substring(p1 + 1, p2);
        String mname = dec.substring(p2 + 1);

        ClassLoader ld = caller.lookupClass().getClassLoader();
        Class<?> oc = Class.forName(owner.replace('/', '.'), false, ld);
        // The JVM already resolved the target descriptor in the indy MethodType.
        // Instance sites prepend exactly one receiver parameter.
        MethodType mt = kind == '0' ? type : type.dropParameterTypes(0, 1);

        MethodHandle mh;
        if (kind == '0') {
            mh = caller.findStatic(oc, mname, mt);
        } else if (kind == '3') {
            mh = caller.findSpecial(oc, mname, mt, caller.lookupClass());
        } else {
            mh = caller.findVirtual(oc, mname, mt);
        }
        return new ConstantCallSite(mh.asType(type));
    }

    private static int embeddedSecret() { return 0x13579BDF; }
    private static int embeddedSecret2() { return 0x2468ACE1; }
    private static int embeddedMode() { return 0x10203047; }

    private static int mix(int a, int b, int n, int c, int t, int nonce) {
        int h = embeddedSecret() ^ Integer.rotateLeft(embeddedSecret2(), embeddedMode() & 31);
        h = Integer.rotateLeft(h + a, 7) ^ b;
        h = (h ^ n) * 0x85EBCA6B;
        h = Integer.rotateLeft(h + c, 13) ^ t ^ nonce;
        h ^= h >>> 16;
        h *= 0xC2B2AE35;
        return h ^ (h >>> 13);
    }

    private static String crypt(String s, int key, int mul, int add, int nonce) {
        char[] c = s.toCharArray();
        int k = key;
        int mode = embeddedMode() & 7;
        for (int i = 0; i < c.length; i++) {
            int lo = k & 255;
            int hi = (k >>> 16) & 255;
            int v = c[i];
            int mask = Integer.rotateLeft(k ^ nonce, (mode + i) & 31) & 255;
            int r = ((k >>> 27) + mode + i) & 7;
            v ^= mask;
            v = (v - hi) & 255;
            v = ((v >>> r) | (v << (8 - r))) & 255;
            c[i] = (char) (v ^ lo);
            k = nextState(k, mul, add, mode, i);
        }
        // Decode code units in place, retaining supplementary and isolated surrogates.
        int length = 0;
        for (int i = 0; i < c.length;) {
            int first = c[i++];
            if (first < 0x80) c[length++] = (char) first;
            else if (first < 0xe0)
                c[length++] = (char) (((first & 31) << 6) | (c[i++] & 63));
            else {
                int second = c[i++] & 63;
                c[length++] = (char) (((first & 15) << 12) | (second << 6) | (c[i++] & 63));
            }
        }
        return new String(c, 0, length);
    }

    private static int nextState(int k, int mul, int add, int mode, int i) {
        return switch (mode) {
            case 0 -> Integer.rotateLeft(k * mul + add + i, 5);
            case 1 -> Integer.rotateRight((k ^ mul) + add + i, 7);
            case 2 -> Integer.rotateLeft(k + add, 11) ^ mul ^ i;
            case 3 -> (Integer.rotateRight(k, 3) + mul) ^ (add + i);
            case 4 -> Integer.rotateLeft(k ^ add ^ i, 9) + mul;
            case 5 -> (k + Integer.rotateLeft(mul, i & 31)) ^ add;
            case 6 -> Integer.rotateRight(k * (mul | 1), 13) + add + i;
            default -> Integer.rotateLeft(k + mul + i, 17) ^ add;
        };
    }
}
