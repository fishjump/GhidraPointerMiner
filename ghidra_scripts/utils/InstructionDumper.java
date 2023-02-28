package utils;

import java.util.Set;
import java.util.TreeSet;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import ghidra.program.model.pcode.PcodeOp;

public class InstructionDumper {

    private final PcodeOp pcodeOp;
    private final int id;

    public InstructionDumper(final PcodeOp pcodeOp, final IDGenerator idGenerator) {
        this.pcodeOp = pcodeOp;
        this.id = idGenerator.next();
    }

    public JsonObject toJson() {
        final var jsonObject = new JsonObject();
        final var jsonArray = new JsonArray();

        jsonObject.addProperty("id", id);

        jsonObject.addProperty("type", "instruction");

        jsonObject.addProperty("operation", PcodeOpNames.get(pcodeOp.getOpcode()));

        if (pcodeOp.isAssignment()) {
            jsonObject.addProperty("result", pcodeOp.getOutput().toString());
        } else {
            jsonObject.add("result", null);
        }

        for (final var input : pcodeOp.getInputs()) {
            jsonArray.add(input.toString());
        }
        jsonObject.add("operands", jsonArray);

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
