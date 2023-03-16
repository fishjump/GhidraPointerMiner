package dumper;

import java.util.stream.Collectors;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import dumper.utils.Controlflow;
import dumper.utils.PcodeOpString;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.pcode.PcodeOp;

public class InstructionDumper {

    private final PcodeOp pcodeOp;
    private final CodeBlock parent;
    private final Controlflow controlflow;

    private final int id;

    public InstructionDumper(PcodeOp pcodeOp, CodeBlock parent, Controlflow controlflow) {
        this.parent = parent;
        this.pcodeOp = pcodeOp;
        this.controlflow = controlflow;

        this.id = this.pcodeOp.getSeqnum().getOrder();
    }

    public JsonObject toJson() {
        final var jsonObject = new JsonObject();

        jsonObject.addProperty("id", id);

        jsonObject.addProperty("type", "instruction");
        jsonObject.addProperty("parent", parent.getFirstStartAddress().toString());
        jsonObject.addProperty("operation", PcodeOpString.get(pcodeOp.getOpcode()));

        if (pcodeOp.isAssignment()) {
            jsonObject.addProperty("result", pcodeOp.getOutput().toString());
        } else {
            jsonObject.add("result", null);
        }

        final var operandsArray = new JsonArray();
        for (final var input : pcodeOp.getInputs()) {
            operandsArray.add(input.toString());
        }
        jsonObject.add("operands", operandsArray);

        final var predArray = new JsonArray();
        var instsInBlock = controlflow.getBasicBlockToPcodeOp().get(parent);
        var pred = instsInBlock.stream().filter(pcode -> pcode.getSeqnum().getOrder() == id - 1)
                .collect(Collectors.toList());
        if (pred.size() == 1) { // has in-block predecessor
            predArray.add(id - 1);
        } else { // find in predecessor basicblocks
            var predBlocks = controlflow.getPredecessors().get(parent);
            for (var block : predBlocks) {
                var insts = controlflow.getBasicBlockToPcodeOp().get(block);
                assert (insts.size() > 0);

                var lastInst = insts.get(insts.size() - 1);
                predArray.add(lastInst.getSeqnum().getOrder());
            }
        }
        jsonObject.add("preds", predArray);

        final var succArray = new JsonArray();
        var succ = instsInBlock.stream().filter(pcode -> pcode.getSeqnum().getOrder() == id + 1)
                .collect(Collectors.toList());
        if (succ.size() == 1) { // has in-block successor
            succArray.add(id + 1);
        } else {// find in successor basicblocks
            var succBlocks = controlflow.getSuccessors().get(parent);
            for (var block : succBlocks) {
                var insts = controlflow.getBasicBlockToPcodeOp().get(block);
                assert (insts.size() > 0);

                var firstInst = insts.get(0);
                predArray.add(firstInst.getSeqnum().getOrder());
            }
        }
        jsonObject.add("succs", succArray);

        return jsonObject;
    }

}
