package utils;

import java.util.ArrayList;

import ghidra.program.model.block.CodeBlock;

public class BasicBlockContext {

    public ArrayList<CodeBlock> succs = new ArrayList<>();
    public ArrayList<CodeBlock> preds = new ArrayList<>();

}
