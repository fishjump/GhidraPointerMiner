package utils;

import java.util.HashMap;

import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.util.task.TaskMonitor;

public class CFG {
    final private String name;
    final private HashMap<CodeBlock, BasicBlockContext> bbCtxMap;

    public CFG(String name, CodeBlockIterator iter, TaskMonitor monitor) throws Exception {
        this.name = name;
        bbCtxMap = new HashMap<>();

        while (iter.hasNext()) {
            var bb = iter.next();
            var ctx = new BasicBlockContext();

            var pIter = bb.getSources(monitor);
            while (pIter.hasNext()) {
                var pred = pIter.next().getSourceBlock();
                ctx.preds.add(pred);
            }

            var sIter = bb.getDestinations(monitor);
            while (sIter.hasNext()) {
                var succ = sIter.next().getDestinationBlock();
                ctx.succs.add(succ);
            }

            bbCtxMap.put(bb, ctx);
        }
    }

    public String genDot() {
        var sb = new StringBuilder();

        sb.append(String.format("digraph %s {\n", name));

        int i = 0;
        for (var set : bbCtxMap.entrySet()) {
            var bb = set.getKey();

            sb.append(String.format("    \"%s\"[label=\"Block%d\"]\n",
                bb.getStartAddresses().toString(), i));
            i++;

        }

        for (var set : bbCtxMap.entrySet()) {
            var bb = set.getKey();
            var ctx = set.getValue();

            for (var succ : ctx.succs) {
                sb.append(String.format("    \"%s\" -> \"%s\"\n",
                    bb.getStartAddresses().toString(), succ.getStartAddresses().toString()));
            }
        }

        sb.append(String.format("}\n", name));

        return sb.toString();
    }
}
