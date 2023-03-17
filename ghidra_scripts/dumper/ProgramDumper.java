package dumper;

import java.util.ArrayList;
import java.util.List;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;

public class ProgramDumper {
    private final Program program;
    private final List<Function> functions;

    public ProgramDumper(Program program) {
        this.program = program;

        functions = new ArrayList<>();
        for (final var function : this.program.getFunctionManager().getFunctionsNoStubs(true)) {
            if (function.isExternal() || function.isThunk()) {
                continue;
            }
            functions.add(function);
        }
    }

    public JsonObject toJson() {
        final var jsonObject = new JsonObject();
        final var jsonArray = new JsonArray();
        for (final var function : functions) {
            try {
                var functionDumper = new FunctionDumper(program, function);
                jsonArray.add(functionDumper.toJson());
            } catch (CancelledException e) {
                e.printStackTrace();
            }
        }

        jsonObject.addProperty("type", "program");
        jsonObject.add("functions", jsonArray);

        return jsonObject;
    }

}
