package utils;

import ghidra.program.model.pcode.PcodeBlock;
import ghidra.program.model.pcode.PcodeBlockBasic;

public class ComparablePcodeBasicBlock implements Comparable<ComparablePcodeBasicBlock> {
    private final PcodeBlockBasic block;

    public ComparablePcodeBasicBlock(PcodeBlockBasic block) {
        this.block = block;
    }

    public PcodeBlock unwrap() {
        return block;
    }

    @Override
    public int compareTo(ComparablePcodeBasicBlock rhs) {
        return this.block.getStart().compareTo(rhs.block.getStart());
    }

    public String dumpInstructions() {
        var sb = new StringBuilder();

        var iter = block.getIterator();
        while (iter.hasNext()) {
            var inst = iter.next();
            sb.append(inst);
            sb.append("\\n");
        }

        return sb.toString();
    }
}
