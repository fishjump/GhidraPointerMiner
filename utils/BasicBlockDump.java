package utils;

import java.util.ArrayList;
import java.util.TreeSet;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import ghidra.program.model.pcode.PcodeBlockBasic;
import ghidra.program.model.pcode.PcodeOp;

public class BasicBlockDump {
    private PcodeBlockBasic block_;
    private ArrayList<PcodeOp> insts_;

    public BasicBlockDump(PcodeBlockBasic block) {
        block_ = block;
    }

    public JsonObject toJson() {
        dumpInstructions();

        var jsonObj = new JsonObject();
        var jsonArr = new JsonArray();
        for (var inst : insts_) {
            var dump = new InstructionDump(inst);
            jsonArr.add(dump.toJson());
        }

        jsonObj.addProperty("type", "basic-block");
        jsonObj.add("instructions", jsonArr);

        return jsonObj;
    }

    private void dumpInstructions() {
        if (insts_ != null) {
            return;
        }
        insts_ = new ArrayList<>();
        var iIt = block_.getIterator();
        while (iIt.hasNext()) {
            var inst = iIt.next();
            insts_.add(inst);
        }
    }

    public TreeSet<VarnodeWrapper> getVars() {
        dumpInstructions();
        var vars = new TreeSet<VarnodeWrapper>();
        for (var insts : insts_) {
            var dump = new InstructionDump(insts);
            vars.addAll(dump.getVars());
        }
        return vars;
    }

}
