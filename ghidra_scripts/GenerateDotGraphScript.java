package ghidra_scripts;
// Generate dot graph for the current program
// @category PCode

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.script.GhidraScript;
import ghidra_scripts.utils.Controlflow;

public class GenerateDotGraphScript extends GhidraScript {
    private final DecompInterface decompiler;

    public GenerateDotGraphScript() {
        decompiler = new DecompInterface();
        decompiler.setOptions(new DecompileOptions());
    }

    @Override
    public void run() throws Exception {
        decompiler.openProgram(currentProgram);

        for (var function : currentProgram.getFunctionManager().getFunctionsNoStubs(true)) {
            if (function.isThunk()) {
                continue;
            }

            var decompilationResult = decompiler.decompileFunction(function, 30, null);
            var highFunction = decompilationResult.getHighFunction();
            if (highFunction == null) {
                continue;
            }

            var controlflow = new Controlflow(highFunction);
            var dotGraph = controlflow.generateDotGraph();
            printf("CFG for function '%s':\n%s\n", function.getName(), dotGraph);
        }
    }
}
