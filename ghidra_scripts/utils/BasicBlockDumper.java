package utils;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import ghidra.program.model.pcode.PcodeBlockBasic;
import ghidra.program.model.pcode.PcodeOp;

public class BasicBlockDumper {

    private final PcodeBlockBasic pcodeBlockBasic;
    private final BasicBlockContext basicBlockContext;
    private final FunctionDumper parentDumper;
    private final IDGenerator idGenerator;
    private final List<PcodeOp> instructions;
    private final List<InstructionDumper> dumpers;
    private final Map<Integer, InstructionDumper> idDumperMap;
    private final String Id;

    public BasicBlockDumper(final PcodeBlockBasic pcodeBlockBasic, final BasicBlockContext basicBlockContext,
            final FunctionDumper parentDumper) {
        this.pcodeBlockBasic = pcodeBlockBasic;
        this.basicBlockContext = basicBlockContext;
        this.parentDumper = parentDumper;
        this.idGenerator = parentDumper.getIdGenerator();
        this.Id = pcodeBlockBasic.getStart().toString();

        this.instructions = new ArrayList<>();
        final var iterator = pcodeBlockBasic.getIterator();
        while (iterator.hasNext()) {
            final var instruction = iterator.next();
            instructions.add(instruction);
        }

        this.dumpers = new ArrayList<>();
        for (final var instruction : instructions) {
            this.dumpers.add(new InstructionDumper(instruction, this));
        }

        this.idDumperMap = new TreeMap<>();
        for (final var dumper : dumpers) {
            idDumperMap.put(dumper.getId(), dumper);
        }
    }

    public JsonObject toJson() {
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
        for (final var dumper : dumpers) {
            instructionsArray.add(dumper.getId());
        }
        jsonObject.add("instructions", instructionsArray);

        return jsonObject;
    }

    public Set<VarnodeWrapper> getVarnodeWrappers() {
        final var varnodeWrappers = new TreeSet<VarnodeWrapper>();
        for (final var dumper : dumpers) {
            varnodeWrappers.addAll(dumper.getVarnodeWrappers());
        }
        return varnodeWrappers;
    }

    public List<InstructionDumper> getInstructionDumpers() {
        return dumpers;
    }

    public BasicBlockContext getBasicBlockContext() {
        return basicBlockContext;
    }

    public Map<Integer, InstructionDumper> getIdDumperMap() {
        return idDumperMap;
    }

    public FunctionDumper getParentDumper() {
        return parentDumper;
    }

    public IDGenerator getIdGenerator() {
        return idGenerator;
    }

    public String getId() {
        return Id;
    }

}
