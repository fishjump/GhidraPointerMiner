package utils;

import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeBlockBasic;

public class FunctionDumper {

    private final HighFunction highFunction;
    private final Controlflow controlflow;
    private Map<PcodeBlockBasicWrapper, BasicBlockContext> basicBlockContexts;

    public FunctionDumper(final HighFunction highFunction) {
        this.highFunction = highFunction;
        this.controlflow = new Controlflow(highFunction);
    }

    public JsonObject toJson() {
        dumpBasicBlockContextsIfNecessary();

        final var jsonObject = new JsonObject();
        jsonObject.addProperty("type", "function");
        jsonObject.addProperty("name", highFunction.getFunction().getName());
        final var basicBlockArray = new JsonArray();
        for (final var entry : basicBlockContexts.entrySet()) {
            if (!(entry.getKey().unwrap() instanceof PcodeBlockBasic)) {
                continue;
            }
            final var basicBlock = (PcodeBlockBasic) entry.getKey().unwrap();
            final var basicBlockDumper = new BasicBlockDumper(basicBlock, entry.getValue());
            basicBlockArray.add(basicBlockDumper.toJson());
        }
        jsonObject.add("basic-blocks", basicBlockArray);

        final var variableArray = new JsonArray();
        for (final var var : getVarnodeWrappers()) {
            variableArray.add(var.unwrap().toString());
        }
        jsonObject.add("variables", variableArray);

        return jsonObject;
    }

    private void dumpBasicBlockContextsIfNecessary() {
        if (basicBlockContexts != null) {
            return;
        }

        basicBlockContexts = controlflow.getBasicBlockContexts();
    }

    public Set<VarnodeWrapper> getVarnodeWrappers() {
        dumpBasicBlockContextsIfNecessary();

        final var varnodeWrappers = new TreeSet<VarnodeWrapper>();
        for (final var entry : basicBlockContexts.entrySet()) {
            if (!(entry.getKey().unwrap() instanceof PcodeBlockBasic)) {
                continue;
            }
            final var basicBlock = (PcodeBlockBasic) entry.getKey().unwrap();
            final var basicBlockDumper = new BasicBlockDumper(basicBlock, entry.getValue());
            varnodeWrappers.addAll(basicBlockDumper.getVarnodeWrappers());
        }
        return varnodeWrappers;
    }

}
