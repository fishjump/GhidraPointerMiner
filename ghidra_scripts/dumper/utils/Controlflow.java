package dumper.utils;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class Controlflow {
    private final Program program;
    private final Function function;
    private final BasicBlockModel basicBlockModel;

    private final Map<CodeBlockWrapper, List<PcodeOp>> basicBlockToPcodeOp;
    private final Map<CodeBlockWrapper, List<CodeBlockWrapper>> predecessors;
    private final Map<CodeBlockWrapper, List<CodeBlockWrapper>> successors;

    private CodeBlockWrapper entry;
    private CodeBlockWrapper exit;

    public Controlflow(Program program, Function function)
            throws CancelledException {
        entry = null;
        exit = null;

        this.program = program;
        this.function = function;
        this.basicBlockModel = new BasicBlockModel(this.program);

        this.basicBlockToPcodeOp = new TreeMap<>();
        for (var block : basicBlockModel.getCodeBlocks(TaskMonitor.DUMMY)) {
            if (function.getBody().contains(block.getFirstStartAddress())) {
                basicBlockToPcodeOp.put(new CodeBlockWrapper(block), new ArrayList<>());
            }
        }

        this.predecessors = new TreeMap<>();
        this.successors = new TreeMap<>();

        for (var pair : basicBlockToPcodeOp.entrySet()) {
            var basicBlock = pair.getKey();

            var preds = new ArrayList<CodeBlockWrapper>();
            var edgesIn = basicBlock.unwrap().getSources(TaskMonitor.DUMMY);
            while (edgesIn.hasNext()) {
                var edge = edgesIn.next();
                var pred = edge.getSourceBlock();
                if (function.getBody().contains(pred.getFirstStartAddress())) {
                    preds.add(new CodeBlockWrapper(edge.getSourceBlock()));
                }
            }
            predecessors.put(basicBlock, preds);

            var succs = new ArrayList<CodeBlockWrapper>();
            var edgesOut = basicBlock.unwrap().getDestinations(TaskMonitor.DUMMY);
            while (edgesOut.hasNext()) {
                var edge = edgesOut.next();
                var succ = edge.getDestinationBlock();
                if (function.getBody().contains(succ.getFirstStartAddress())) {
                    succs.add(new CodeBlockWrapper(edge.getDestinationBlock()));
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

    public Function getFunction() {
        return function;
    }

    public Map<CodeBlockWrapper, List<CodeBlockWrapper>> getPredecessors() {
        return predecessors;
    }

    public Map<CodeBlockWrapper, List<CodeBlockWrapper>> getSuccessors() {
        return successors;
    }

    public Map<CodeBlockWrapper, List<PcodeOp>> getBasicBlockToPcodeOp() {
        return basicBlockToPcodeOp;
    }
}
