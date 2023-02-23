package utils;

import java.util.TreeMap;

import ghidra.program.model.pcode.HighFunction;

public class Controlflow {
    private final HighFunction highFunction;
    private final TreeMap<PcodeBlockBasicWrapper, BasicBlockContext> basicBlockContexts;
    private final BasicBlockContext entry;
    private final BasicBlockContext exit;

    public Controlflow(final HighFunction highFunction) {
        this.highFunction = highFunction;
        basicBlockContexts = new TreeMap<>();
        entry = new BasicBlockContext();
        exit = new BasicBlockContext();

        for (final var basicBlock : highFunction.getBasicBlocks()) {
            final var context = new BasicBlockContext();

            if (basicBlock.getInSize() == 0) {
                entry.succs.add(basicBlock);
            } else {
                for (int i = 0; i < basicBlock.getInSize(); i++) {
                    final var predecessor = basicBlock.getIn(i);
                    context.preds.add(predecessor);
                }
            }

            if (basicBlock.getOutSize() == 0) {
                exit.preds.add(basicBlock);
            } else {
                for (int i = 0; i < basicBlock.getOutSize(); i++) {
                    final var successor = basicBlock.getOut(i);
                    context.succs.add(successor);
                }
            }

            basicBlockContexts.put(new PcodeBlockBasicWrapper(basicBlock), context);
        }
    }

    public TreeMap<PcodeBlockBasicWrapper, BasicBlockContext> getBasicBlockContexts() {
        return basicBlockContexts;
    }

    public String generateDotGraph() {
        final var sb = new StringBuilder();

        sb.append(String.format("digraph %s {\n", highFunction.getFunction().getName()));
        sb.append("    \"entry\"[label=\"Entry\"]\n");
        sb.append("    \"exit\"[label=\"Exit\"]\n");

        int i = 0;
        for (final var entry : basicBlockContexts.entrySet()) {
            final var basicBlock = entry.getKey();
            sb.append(String.format("    \"%s\"[label=\"Block%d:%s\n%s\"]\n",
                    basicBlock.unwrap().getStart().toString(), i,
                    basicBlock.unwrap().getStart().toString(), basicBlock.dumpInstructions()));
            i++;
        }

        for (final var basicBlock : entry.succs) {
            sb.append(
                    String.format("    \"entry\" -> \"%s\"\n", basicBlock.getStart().toString()));
        }

        for (final var basicBlock : exit.preds) {
            sb.append(
                    String.format("    \"%s\" -> \"exit\"\n", basicBlock.getStart().toString()));
        }

        for (final var entry : basicBlockContexts.entrySet()) {
            final var basicBlock = entry.getKey();
            final var context = entry.getValue();

            for (final var successor : context.succs) {
                sb.append(String.format("    \"%s\" -> \"%s\"\n",
                        basicBlock.unwrap().getStart().toString(),
                        successor.getStart().toString()));
            }
        }

        sb.append(String.format("}\n", highFunction.getFunction().getName()));

        return sb.toString();
    }
}
