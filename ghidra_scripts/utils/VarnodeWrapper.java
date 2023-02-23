package ghidra_scripts.utils;

import ghidra.program.model.pcode.Varnode;

public class VarnodeWrapper implements Comparable<VarnodeWrapper> {
    private final Varnode varnode;

    public VarnodeWrapper(Varnode varnode) {
        this.varnode = varnode;
    }

    public Varnode unwrap() {
        return varnode;
    }

    @Override
    public int compareTo(VarnodeWrapper other) {
        return varnode.toString().compareTo(other.unwrap().toString());
    }
}
