package ghidra_scripts.utils;

import java.util.ArrayList;

import ghidra.program.model.pcode.PcodeBlock;

public class BasicBlockContext {

    public ArrayList<PcodeBlock> succs = new ArrayList<>();
    public ArrayList<PcodeBlock> preds = new ArrayList<>();

}
