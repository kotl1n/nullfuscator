package com.nullfuscator.obf.transform;

import com.nullfuscator.obf.core.ObfContext;
import com.nullfuscator.obf.core.Transformer;
import org.objectweb.asm.Attribute;
import org.objectweb.asm.ByteVector;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.tree.ClassNode;

import java.util.ArrayList;
import java.util.Random;

public final class FileCrasherTransformer implements Transformer {

    private static final String ATTR_NAME = "Ez$Junk";

    private static final int MIN_LEN = 48;
    private static final int MAX_LEN = 256;

    @Override public String id() { return "fileCrasher"; }

    @Override public String description() { return "attach ignorable junk class attribute"; }

    @Override
    public void transform(ObfContext ctx) {
        Random rnd = ctx.random();
        int count = 0;
        for (ClassNode cn : ctx.targets(id())) {
            int len = MIN_LEN + rnd.nextInt(MAX_LEN - MIN_LEN + 1);
            byte[] junk = new byte[len];
            rnd.nextBytes(junk);
            if (cn.attrs == null) cn.attrs = new ArrayList<>();
            cn.attrs.add(new JunkAttribute(junk));
            count++;
        }
        ctx.log().debug("fileCrasher: attached junk attribute to " + count + " classes");
    }

    private static final class JunkAttribute extends Attribute {
        private final byte[] data;

        JunkAttribute(byte[] data) {
            super(ATTR_NAME);
            this.data = data;
        }

        @Override
        protected ByteVector write(ClassWriter cw, byte[] code, int codeLen,
                                   int maxStack, int maxLocals) {
            ByteVector bv = new ByteVector(data.length);
            bv.putByteArray(data, 0, data.length);
            return bv;
        }
    }
}
