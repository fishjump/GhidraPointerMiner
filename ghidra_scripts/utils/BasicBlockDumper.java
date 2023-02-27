package utils;

import java.util.ArrayList;
import java.util.Set;
import java.util.TreeSet;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import ghidra.program.model.pcode.PcodeBlockBasic;
import ghidra.program.model.pcode.PcodeOp;

public class BasicBlockDumper {

    private final PcodeBlockBasic pcodeBlockBasic;
    private final BasicBlockContext basicBlockContext;
    private final IDGenerator idGenerator;
    private ArrayList<PcodeOp> instructions;

    public BasicBlockDumper(final PcodeBlockBasic pcodeBlockBasic, final BasicBlockContext basicBlockContext,
            final IDGenerator idGenerator) {
        this.pcodeBlockBasic = pcodeBlockBasic;
        this.basicBlockContext = basicBlockContext;
        this.idGenerator = idGenerator;
    }

    public BasicBlockDumper(PcodeBlockBasic pcodeBlockBasic, BasicBlockContext basicBlockContext) {
        this.pcodeBlockBasic = pcodeBlockBasic;
        this.basicBlockContext = basicBlockContext;
        this.idGenerator = null;
    }

    public JsonObject toJson() {
        dumpInstructionsIfNecessary();

        final var jsonObject = new JsonObject();
        jsonObject.addProperty("type", "basic-block");
        jsonObject.addProperty("id", pcodeBlockBasic.getStart().toString());

        final var predsArray = new JsonArray();
        for (final var pred : basicBlockContext.preds) {
            predsArray.add(pred.getStart().toString());
        }
        jsonObject.add("preds", predsArray);

        final var succsArray = new JsonArray();
        for (final var succ : basicBlockContext.succs) {
            succsArray.add(succ.getStart().toString());
        }
        jsonObject.add("succs", succsArray);

        final var instructionsArray = new JsonArray();
        for (final var instruction : instructions) {
            final var instructionDumper = new InstructionDumper(instruction, idGenerator);
            instructionsArray.add(instructionDumper.toJson());
        }
        jsonObject.add("instructions", instructionsArray);

        return jsonObject;
    }

    private void dumpInstructionsIfNecessary() {
        if (instructions != null) {
            return;
        }

        instructions = new ArrayList<>();
        final var iterator = pcodeBlockBasic.getIterator();
        while (iterator.hasNext()) {
            final var instruction = iterator.next();
            instructions.add(instruction);
        }
    }

    public Set<VarnodeWrapper> getVarnodeWrappers() {
        dumpInstructionsIfNecessary();

        final var varnodeWrappers = new TreeSet<VarnodeWrapper>();
        for (final var instruction : instructions) {
            final var instructionDumper = new InstructionDumper(instruction);
            varnodeWrappers.addAll(instructionDumper.getVarnodeWrappers());
        }
        return varnodeWrappers;
    }
}
