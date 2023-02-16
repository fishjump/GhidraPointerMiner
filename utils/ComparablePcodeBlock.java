package utils;

import ghidra.program.model.pcode.PcodeBlock;

public class ComparablePcodeBlock implements Comparable<ComparablePcodeBlock> {
    private final PcodeBlock block;

    public ComparablePcodeBlock(PcodeBlock block) {
        this.block = block;
    }

    public PcodeBlock unwrap() {
        return block;
    }

    @Override
    public int compareTo(ComparablePcodeBlock rhs) {
        return this.block.getStart().compareTo(rhs.block.getStart());
    }
}
