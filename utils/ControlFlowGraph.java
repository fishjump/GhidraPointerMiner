package utils;

import java.util.TreeMap;

import ghidra.program.model.pcode.HighFunction;

public class ControlFlowGraph {
    final private HighFunction f;
    final private TreeMap<ComparablePcodeBasicBlock, BasicBlockContext> bbCtxMap;

    final private BasicBlockContext entry;
    final private BasicBlockContext exit;

    public ControlFlowGraph(HighFunction f)
            throws Exception {
        this.f = f;
        bbCtxMap = new TreeMap<>();
        entry = new BasicBlockContext();
        exit = new BasicBlockContext();

        var bbList = f.getBasicBlocks();
        bbList.forEach(bb -> {
            var ctx = new BasicBlockContext();

            if (bb.getInSize() == 0) {
                entry.succs.add(bb);
            } else {
                for (int i = 0; i < bb.getInSize(); i++) {
                    var pred = bb.getIn(i);
                    ctx.preds.add(pred);
                }
            }

            if (bb.getOutSize() == 0) {
                exit.preds.add(bb);
            } else {
                for (int i = 0; i < bb.getOutSize(); i++) {
                    var succ = bb.getOut(i);
                    ctx.succs.add(succ);
                }
            }

            bbCtxMap.put(new ComparablePcodeBasicBlock(bb), ctx);
        });

    }

    public String genDot() {
        var sb = new StringBuilder();

        sb.append(String.format("digraph %s {\n", f.getFunction().getName()));
        sb.append("    \"entry\"[label=\"Entry\"]\n");
        sb.append("    \"exit\"[label=\"Exit\"]\n");

        int i = 0;
        for (var set : bbCtxMap.entrySet()) {
            var bb = set.getKey();
            sb.append(String.format("    \"%s\"[label=\"Block%d:%s\n%s\"]\n",
                    bb.unwrap().getStart().toString(), i,
                    bb.unwrap().getStart().toString(), bb.dumpInstructions()));
            i++;

        }

        for (var bb : entry.succs) {
            sb.append(
                    String.format("    \"entry\" -> \"%s\"\n", bb.getStart().toString()));
        }

        for (var bb : exit.preds) {
            sb.append(
                    String.format("    \"%s\" -> \"exit\"\n", bb.getStart().toString()));
        }

        for (var set : bbCtxMap.entrySet()) {
            var bb = set.getKey();
            var ctx = set.getValue();

            for (var succ : ctx.succs) {
                sb.append(String.format("    \"%s\" -> \"%s\"\n",
                        bb.unwrap().getStart().toString(),
                        succ.getStart().toString()));
            }
        }

        sb.append(String.format("}\n", f.getFunction().getName()));

        return sb.toString();
    }
}
