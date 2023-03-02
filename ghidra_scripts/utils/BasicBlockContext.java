package utils;

import java.util.ArrayList;

import ghidra.program.model.pcode.PcodeBlockBasic;

public class BasicBlockContext {

    public ArrayList<PcodeBlockBasic> succs = new ArrayList<>();
    public ArrayList<PcodeBlockBasic> preds = new ArrayList<>();

}
