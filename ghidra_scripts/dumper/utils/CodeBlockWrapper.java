package dumper.utils;

import ghidra.program.model.block.CodeBlock;

public class CodeBlockWrapper implements Comparable<CodeBlockWrapper> {

    private final CodeBlock codeBlock;

    public CodeBlockWrapper(CodeBlock codeBlock) {
        this.codeBlock = codeBlock;
    }

    public CodeBlock unwrap() {
        return codeBlock;
    }

    @Override
    public int compareTo(CodeBlockWrapper other) {
        return this.codeBlock.getFirstRange().compareTo(other.codeBlock.getFirstRange());
    }

}
