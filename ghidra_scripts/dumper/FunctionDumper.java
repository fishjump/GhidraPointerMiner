package dumper;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import dumper.utils.Controlflow;
import dumper.utils.SeqCounter;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class FunctionDumper {
    private final Program program;
    private final Function function;

    private final SeqCounter counter;
    private final Controlflow controlflow;

    private final Map<CodeBlock, List<PcodeOp>> basicBlockToPcodeOp;
    private final List<VarnodeWrapper> varnodes;
    private final BasicBlockModel basicBlockModel;

    private final ArrayList<InstructionDumper> instructionDumpers;

    public FunctionDumper(Program program, Function function) throws CancelledException {
        this.program = program;
        this.function = function;

        this.counter = new SeqCounter();

        this.basicBlockToPcodeOp = new HashMap<>();
        this.varnodes = new ArrayList<>();
        this.basicBlockModel = new BasicBlockModel(this.program);

        this.instructionDumpers = new ArrayList<>();

        for (var block : basicBlockModel.getCodeBlocks(TaskMonitor.DUMMY)) {
            if (function.getBody().contains(block.getFirstStartAddress())) {
                basicBlockToPcodeOp.put(block, new ArrayList<>());
            }
        }

        this.controlflow = new Controlflow(function, basicBlockToPcodeOp);

        var insts = program.getListing().getInstructions(function.getBody(),
                true);
        for (var inst : insts) {
            CodeBlock parent = null;
            List<PcodeOp> list = null;
            for (var pair : basicBlockToPcodeOp.entrySet()) {
                if (pair.getKey().contains(inst.getAddress())) {
                    parent = pair.getKey();
                    list = pair.getValue();
                    break;
                }
            }
            assert (parent != null && list != null);

            for (var pcode : inst.getPcode()) {
                pcode.getSeqnum().setOrder(counter.next());
                list.add(pcode);
                if (pcode.isAssignment()) {
                    varnodes.add(new VarnodeWrapper(pcode.getOutput()));
                }
                for (var input : pcode.getInputs()) {
                    varnodes.add(new VarnodeWrapper(input));
                }
            }
        }

        for (var pair : basicBlockToPcodeOp.entrySet()) {
            CodeBlock parent = pair.getKey();
            List<PcodeOp> list = pair.getValue();
            for (var inst : list) {
                instructionDumpers.add(new InstructionDumper(inst, parent, controlflow));
            }
        }

    }

    public JsonObject toJson() {
        final var jsonObject = new JsonObject();
        jsonObject.addProperty("type", "function");
        jsonObject.addProperty("name", function.getName());

        final var variableArray = new JsonArray();
        for (final var var : varnodes) {
            variableArray.add(var.unwrap().toString());
        }
        jsonObject.add("variables", variableArray);

        final var instArray = new JsonArray();
        for (final var dumper : instructionDumpers) {
            instArray.add(dumper.toJson());
        }

        jsonObject.add("instructions", instArray);

        final var basicBlockArray = new JsonArray();
        // for (final var dumper : dumpers) {
        // basicBlockArray.add(dumper.toJson());
        // }
        jsonObject.add("basic-blocks", basicBlockArray);

        return jsonObject;
    }

}
