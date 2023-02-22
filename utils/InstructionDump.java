package utils;

import java.util.TreeSet;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import ghidra.program.model.pcode.PcodeOp;

public class InstructionDump {
    private PcodeOp inst_;

    public InstructionDump(PcodeOp inst) {
        inst_ = inst;
    }

    public JsonObject toJson() {
        var jsonObj = new JsonObject();
        var jsonArr = new JsonArray();

        jsonObj.addProperty("type", "instruction");
        jsonObj.addProperty("operation", inst_.getOpcode());
        if (inst_.isAssignment()) {
            jsonObj.addProperty("result", inst_.getOutput().toString());
        } else {
            jsonObj.add("result", null);
        }

        for (var input : inst_.getInputs()) {
            jsonArr.add(input.toString());
        }
        jsonObj.add("operands", jsonArr);

        return jsonObj;
    }

    public TreeSet<VarnodeWrapper> getVars() {
        var vars = new TreeSet<VarnodeWrapper>();
        if (inst_.isAssignment()) {
            vars.add(new VarnodeWrapper(inst_.getOutput()));
        }

        for (var input : inst_.getInputs()) {
            vars.add(new VarnodeWrapper(input));
        }

        return vars;
    }

}
