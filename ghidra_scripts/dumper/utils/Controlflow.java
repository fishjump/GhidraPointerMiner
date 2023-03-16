package dumper.utils;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class Controlflow {
    private final Function function;

    private final Map<CodeBlock, List<PcodeOp>> basicBlockToPcodeOp;
    private final Map<CodeBlock, List<CodeBlock>> predecessors;
    private final Map<CodeBlock, List<CodeBlock>> successors;

    private CodeBlock entry;
    private CodeBlock exit;

    public Controlflow(Function function, Map<CodeBlock, List<PcodeOp>> basicBlockToPcodeOp) throws CancelledException {
        entry = null;
        exit = null;

        this.function = function;

        this.basicBlockToPcodeOp = basicBlockToPcodeOp;
        this.predecessors = new TreeMap<>();
        this.successors = new TreeMap<>();

        for (var pair : basicBlockToPcodeOp.entrySet()) {
            var basicBlock = pair.getKey();

            var preds = new ArrayList<CodeBlock>();
            var edgesIn = basicBlock.getSources(TaskMonitor.DUMMY);
            while (edgesIn.hasNext()) {
                var edge = edgesIn.next();
                var pred = edge.getSourceBlock();
                if (function.getBody().contains(pred.getFirstStartAddress())) {
                    preds.add(edge.getSourceBlock());
                }
            }
            predecessors.put(basicBlock, preds);

            var succs = new ArrayList<CodeBlock>();
            var edgesOut = basicBlock.getDestinations(TaskMonitor.DUMMY);
            while (edgesOut.hasNext()) {
                var edge = edgesOut.next();
                var succ = edge.getDestinationBlock();
                if (function.getBody().contains(succ.getFirstStartAddress())) {
                    succs.add(edge.getSourceBlock());
                }
            }
            successors.put(basicBlock, succs);
        }

        for (var pair : predecessors.entrySet()) {
            var basicBlock = pair.getKey();
            var list = pair.getValue();

            // no predecessor, it's an entry
            if (list.size() == 0) {
                entry = basicBlock;
                break;
            }
        }

        for (var pair : successors.entrySet()) {
            var basicBlock = pair.getKey();
            var list = pair.getValue();

            // no successor, it's an exit
            if (list.size() == 0) {
                exit = basicBlock;
                break;
            }
        }

        assert (entry != null && exit != null);
    }

    public Map<CodeBlock, List<CodeBlock>> getPredecessors() {
        return predecessors;
    }

    public Map<CodeBlock, List<CodeBlock>> getSuccessors() {
        return successors;
    }

    public Map<CodeBlock, List<PcodeOp>> getBasicBlockToPcodeOp() {
        return basicBlockToPcodeOp;
    }
}
