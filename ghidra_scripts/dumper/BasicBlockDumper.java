package dumper;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import dumper.utils.CodeBlockWrapper;
import dumper.utils.Controlflow;

public class BasicBlockDumper {

    private final CodeBlockWrapper codeBlock;
    private final Controlflow controlflow;

    public BasicBlockDumper(CodeBlockWrapper codeBlock, Controlflow controlflow) {
        this.codeBlock = codeBlock;
        this.controlflow = controlflow;
    }

    public JsonObject toJson() {
        final var jsonObject = new JsonObject();
        jsonObject.addProperty("type", "basic-block");
        jsonObject.addProperty("id", codeBlock.unwrap().getFirstStartAddress().toString());

        final var predsArray = new JsonArray();
        for (final var pred : controlflow.getPredecessors().get(codeBlock)) {
            predsArray.add(pred.unwrap().getFirstStartAddress().toString());
        }
        jsonObject.add("preds", predsArray);

        final var succsArray = new JsonArray();
        for (final var succ : controlflow.getSuccessors().get(codeBlock)) {
            succsArray.add(succ.unwrap().getFirstStartAddress().toString());
        }
        jsonObject.add("succs", succsArray);

        final var instructionsArray = new JsonArray();
        for (final var pcodeOp : controlflow.getBasicBlockToPcodeOp().get(codeBlock)) {
            instructionsArray.add(pcodeOp.getSeqnum().getOrder());
        }
        jsonObject.add("instructions", instructionsArray);

        return jsonObject;
    }

}
