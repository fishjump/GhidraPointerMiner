package utils;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import ghidra.program.model.pcode.HighFunction;

public class FunctionDumper {

    private final HighFunction highFunction;
    private final Map<PcodeBlockBasicWrapper, BasicBlockContext> basicBlockContexts;
    private final List<BasicBlockDumper> dumpers;
    private final IDGenerator idGenerator;

    public FunctionDumper(final HighFunction highFunction) {
        this.highFunction = highFunction;
        this.basicBlockContexts = new Controlflow(highFunction).getBasicBlockContexts();
        this.dumpers = new ArrayList<>();
        this.idGenerator = new IDGenerator();

        for (final var entry : basicBlockContexts.entrySet()) {
            final var basicBlock = entry.getKey().unwrap();
            final var basicBlockDumper = new BasicBlockDumper(basicBlock, entry.getValue(), idGenerator);
            dumpers.add(basicBlockDumper);
        }
    }

    public JsonObject toJson() {
        final var jsonObject = new JsonObject();
        jsonObject.addProperty("type", "function");
        jsonObject.addProperty("name", highFunction.getFunction().getName());
        final var basicBlockArray = new JsonArray();
        for (final var dumper : dumpers) {
            basicBlockArray.add(dumper.toJson());
        }
        jsonObject.add("basic-blocks", basicBlockArray);

        final var variableArray = new JsonArray();
        for (final var var : getVarnodeWrappers()) {
            variableArray.add(var.unwrap().toString());
        }
        jsonObject.add("variables", variableArray);

        final var instArray = new JsonArray();
        for (final var dumper : getInstructionDumpers()) {
            instArray.add(dumper.toJson());
        }
        jsonObject.add("instructions", instArray);

        return jsonObject;
    }

    public Set<VarnodeWrapper> getVarnodeWrappers() {
        final var varnodeWrappers = new TreeSet<VarnodeWrapper>();
        for (final var dumper : dumpers) {
            varnodeWrappers.addAll(dumper.getVarnodeWrappers());
        }
        return varnodeWrappers;
    }

    public ArrayList<InstructionDumper> getInstructionDumpers() {
        final var instructionDumpers = new ArrayList<InstructionDumper>();
        for (final var dumper : dumpers) {
            instructionDumpers.addAll(dumper.getInstructionDumpers());
        }
        return instructionDumpers;
    }

}
