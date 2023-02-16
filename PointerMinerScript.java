import ghidra.app.script.GhidraScript;
import ghidra.program.model.block.BasicBlockModel;
import utils.CFG;

public class PointerMinerScript extends GhidraScript {
    @Override
    public void run() throws Exception {
        var bbModel = new BasicBlockModel(currentProgram);
        var funcMgr = currentProgram.getFunctionManager();
        for (var curFunc : funcMgr.getFunctions(true)) {
            printf("Function: %s ( %s )\n", curFunc.getName(),
                curFunc.getEntryPoint());
            var bbIter =
                bbModel.getCodeBlocksContaining(curFunc.getBody(), monitor);
            var cfg = new CFG(curFunc.getName(), bbIter, monitor);
            printf("CFG: %s\n", cfg.genDot());
        }
    }
}
