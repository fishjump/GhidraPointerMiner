package ghidra_scripts.utils;

import ghidra.program.model.pcode.PcodeBlock;
import ghidra.program.model.pcode.PcodeBlockBasic;

public class PcodeBlockBasicWrapper implements Comparable<PcodeBlockBasicWrapper> {
    private final PcodeBlockBasic block;

    public PcodeBlockBasicWrapper(PcodeBlockBasic block) {
        this.block = block;
    }

    public PcodeBlock unwrap() {
        return block;
    }

    @Override
    public int compareTo(PcodeBlockBasicWrapper rhs) {
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
