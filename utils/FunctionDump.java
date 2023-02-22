package utils;

import java.util.ArrayList;
import java.util.TreeSet;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeBlockBasic;

public class FunctionDump {
    private HighFunction hF_;
    private ArrayList<PcodeBlockBasic> blocks_;

    public FunctionDump(HighFunction f) {
        hF_ = f;
    }

    public JsonObject toJson() {
        dumpBasicBlocks();

        var jsonObj = new JsonObject();
        var jsonArr = new JsonArray();
        for (var block : blocks_) {
            var dump = new BasicBlockDump(block);
            jsonArr.add(dump.toJson());
        }

        jsonObj.addProperty("type", "function");
        jsonObj.add("basic-blocks", jsonArr);

        jsonArr = new JsonArray();
        for (var id : getVars()) {
            jsonArr.add(id.unwrap().toString());
        }
        jsonObj.add("variables", jsonArr);

        return jsonObj;
    }

    private void dumpBasicBlocks() {
        if (blocks_ != null) {
            return;
        }

        blocks_ = hF_.getBasicBlocks();
    }

    public TreeSet<VarnodeWrapper> getVars() {
        dumpBasicBlocks();
        var vars = new TreeSet<VarnodeWrapper>();
        for (var block : blocks_) {
            var dump = new BasicBlockDump(block);
            vars.addAll(dump.getVars());
        }
        return vars;
    }

}
