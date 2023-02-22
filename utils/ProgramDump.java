package utils;

import java.util.ArrayList;
import java.util.TreeSet;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;

public class ProgramDump {
    private Program prog_;
    private DecompInterface dIf_;
    private ArrayList<HighFunction> fList_;

    public ProgramDump(Program prog) {
        prog_ = prog;
        dIf_ = new DecompInterface();
        dIf_.setOptions(new DecompileOptions());
    }

    public JsonObject toJson() {
        dumpFunctions();

        var jsonObj = new JsonObject();
        var jsonArr = new JsonArray();
        var identities = new TreeSet<VarnodeWrapper>();
        for (var f : fList_) {
            var dump = new FunctionDump(f);
            jsonArr.add(dump.toJson());
            identities.addAll(dump.getVars());
        }

        jsonObj.addProperty("type", "program");
        jsonObj.add("functions", jsonArr);

        return jsonObj;
    }

    private void dumpFunctions() {
        if (fList_ != null) {
            return;
        }

        dIf_.openProgram(prog_);

        var fMgr = prog_.getFunctionManager();
        var fIt = fMgr.getFunctions(true);
        fList_ = new ArrayList<HighFunction>();
        while (fIt.hasNext()) {
            var f = fIt.next();
            var res = dIf_.decompileFunction(f, 30, null);
            var hF = res.getHighFunction();
            if (hF == null) {
                continue;
            }
            fList_.add(hF);
        }
    }
}
