package utils;

import ghidra.program.model.pcode.Varnode;

public class VarnodeWrapper implements Comparable<VarnodeWrapper> {
    private Varnode var_;

    public VarnodeWrapper(Varnode var) {
        var_ = var;
    }

    public Varnode unwrap() {
        return var_;
    }

    @Override
    public int compareTo(VarnodeWrapper lhs) {
        return var_.toString().compareTo(lhs.unwrap().toString());
    }

}
