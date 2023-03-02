package utils;

import java.util.Set;
import java.util.TreeSet;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import ghidra.program.model.pcode.PcodeOp;

public class InstructionDumper {

    private final PcodeOp pcodeOp;
    private final BasicBlockDumper parentDumper;
    private final int id;

    public InstructionDumper(final PcodeOp pcodeOp, BasicBlockDumper parentDumper) {
        this.pcodeOp = pcodeOp;
        this.parentDumper = parentDumper;
        this.id = parentDumper.getIdGenerator().next();
    }

    public JsonObject toJson() {
        final var jsonObject = new JsonObject();

        jsonObject.addProperty("id", id);

        jsonObject.addProperty("type", "instruction");
        jsonObject.addProperty("parent", pcodeOp.getParent().getStart().toString());
        jsonObject.addProperty("operation", PcodeOpNames.get(pcodeOp.getOpcode()));

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
        if (parentDumper.getIdDumperMap().containsKey(id - 1)) {
            // instruction which is not the begin
            predArray.add(id - 1);
        } else {
            // for the begin instruction of a bb
            final var parentContext = parentDumper.getBasicBlockContext();
            final var functionDumper = parentDumper.getParentDumper();
            final var basicBlockDumperMap = functionDumper.getIdDumperMap();

            for (final var pred : parentContext.preds) {
                assert (basicBlockDumperMap.containsKey(pred.getStart().toString()));

                final var predBlockDumper = basicBlockDumperMap.get(pred.getStart().toString());
                InstructionDumper predInstDumper = null;
                for (var dumper : predBlockDumper.getInstructionDumpers()) {
                    predInstDumper = dumper;
                }
                assert (predInstDumper != null);

                predArray.add(predInstDumper.getId());
            }
        }
        jsonObject.add("pred", predArray);

        final var succArray = new JsonArray();
        if (parentDumper.getIdDumperMap().containsKey(id + 1)) {
            // instruction which is not the end
            succArray.add(id + 1);
        } else {
            // for the end instruction of a bb
            final var parentContext = parentDumper.getBasicBlockContext();
            final var functionDumper = parentDumper.getParentDumper();
            final var basicBlockDumperMap = functionDumper.getIdDumperMap();

            for (final var succ : parentContext.succs) {
                assert (basicBlockDumperMap.containsKey(succ.getStart().toString()));

                final var succBlockDumper = basicBlockDumperMap.get(succ.getStart().toString());
                var succInstDumper = succBlockDumper.getInstructionDumpers().get(0);
                succArray.add(succInstDumper.getId());
            }
        }
        jsonObject.add("succ", succArray);

        return jsonObject;
    }

    public int getId() {
        return this.id;
    }

    public Set<VarnodeWrapper> getVarnodeWrappers() {
        final var varnodeWrappers = new TreeSet<VarnodeWrapper>();
        if (pcodeOp.isAssignment()) {
            varnodeWrappers.add(new VarnodeWrapper(pcodeOp.getOutput()));
        }

        for (final var input : pcodeOp.getInputs()) {
            varnodeWrappers.add(new VarnodeWrapper(input));
        }

        return varnodeWrappers;
    }
}
