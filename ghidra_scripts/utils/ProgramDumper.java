package ghidra_scripts.utils;

import java.util.ArrayList;
import java.util.TreeSet;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;

public class ProgramDumper {

    private final Program program;
    private final DecompInterface decompInterface;
    private ArrayList<HighFunction> functionList;

    public ProgramDumper(final Program program) {
        this.program = program;
        this.decompInterface = new DecompInterface();
        this.decompInterface.setOptions(new DecompileOptions());
    }

    public JsonObject toJson() {
        dumpFunctionIfNecessary();

        final var jsonObject = new JsonObject();
        final var jsonArray = new JsonArray();
        final var identities = new TreeSet<VarnodeWrapper>();
        for (final var highFunction : functionList) {
            final var functionDumper = new FunctionDumper(highFunction);
            jsonArray.add(functionDumper.toJson());
            identities.addAll(functionDumper.getVarnodeWrappers());
        }

        jsonObject.addProperty("type", "program");
        jsonObject.add("functions", jsonArray);

        return jsonObject;
    }

    private void dumpFunctionIfNecessary() {
        if (functionList != null) {
            return;
        }

        decompInterface.openProgram(program);

        functionList = new ArrayList<>();
        for (final var function : program.getFunctionManager().getFunctionsNoStubs(true)) {
            final var decompilationResult = decompInterface.decompileFunction(function, 30, null);
            final var highFunction = decompilationResult.getHighFunction();
            if (highFunction != null) {
                functionList.add(highFunction);
            }
        }
    }
}
