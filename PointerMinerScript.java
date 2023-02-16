import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.script.GhidraScript;
import utils.ControlFlowGraph;

public class PointerMinerScript extends GhidraScript {
    private DecompInterface dIf;

    public PointerMinerScript() {
        dIf = new DecompInterface();
        dIf.setOptions(new DecompileOptions());
    }

    @Override
    public void run() throws Exception {
        dIf.openProgram(currentProgram);

        for (var f = getFirstFunction(); f != null; f = getFunctionAfter(f)) {
            var res = dIf.decompileFunction(f, 30, null);
            var hF = res.getHighFunction();
            if (hF == null) {
                continue;
            }

            var cfg = new ControlFlowGraph(hF);
            printf("CFG: %s\n", cfg.genDot());
        }
    }
}
