package dumper;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import dumper.utils.Controlflow;
import dumper.utils.SeqCounter;
import dumper.utils.VarnodeWrapper;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.util.exception.CancelledException;

public class FunctionDumper {
    private final Program program;
    private final Function function;

    private final SeqCounter counter;
    private final Controlflow controlflow;

    private final Set<VarnodeWrapper> varnodes;

    private final List<InstructionDumper> instructionDumpers;
    private final List<BasicBlockDumper> basicBlockDumpers;
    private final List<PcodeOp> rawPcodes;

    public FunctionDumper(Program program, Function function) throws CancelledException {
        this.program = program;
        this.function = function;
        this.controlflow = new Controlflow(this.program, this.function);

        this.counter = new SeqCounter();

        this.varnodes = new TreeSet<>();

        this.instructionDumpers = new ArrayList<>();
        this.basicBlockDumpers = new ArrayList<>();
        this.rawPcodes = new ArrayList<>();

        var insts = program.getListing().getInstructions(function.getBody(),
                true);
        for (var inst : insts) {
            List<PcodeOp> list = null;
            for (var pair : controlflow.getBasicBlockToPcodeOp().entrySet()) {
                if (pair.getKey().unwrap().contains(inst.getAddress())) {
                    list = pair.getValue();
                    break;
                }
            }
            assert (list != null);

            for (var pcode : inst.getPcode()) {
                pcode.getSeqnum().setOrder(counter.next());
                list.add(pcode);
                rawPcodes.add(pcode);
                if (pcode.isAssignment()) {
                    varnodes.add(new VarnodeWrapper(pcode.getOutput()));
                }
                for (var input : pcode.getInputs()) {
                    varnodes.add(new VarnodeWrapper(input));
                }
            }
        }

        for (var pair : controlflow.getBasicBlockToPcodeOp().entrySet()) {
            var parent = pair.getKey();
            var list = pair.getValue();
            for (var inst : list) {
                instructionDumpers.add(new InstructionDumper(inst, parent, controlflow));
            }
        }

        for (var codeBlock : controlflow.getBasicBlockToPcodeOp().keySet()) {
            basicBlockDumpers.add(new BasicBlockDumper(codeBlock, controlflow));
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
        for (final var dumper : basicBlockDumpers) {
            basicBlockArray.add(dumper.toJson());
        }
        jsonObject.add("basic-blocks", basicBlockArray);

        final var rawArray = new JsonArray();
        for (final var pcode : rawPcodes) {
            rawArray.add(pcode.toString());
        }
        jsonObject.add("raw", rawArray);

        return jsonObject;
    }

}
