package dumper.utils;

import java.util.HashMap;
import java.util.Map;

import ghidra.program.model.pcode.PcodeOp;

public class PcodeOpString {
    private static final Map<Integer, String> opNames = new HashMap<>();

    public static String get(int op) {
        return opNames.get(op);
    }

    static {
        opNames.put(PcodeOp.UNIMPLEMENTED, "UNIMPLEMENTED");
        opNames.put(PcodeOp.COPY, "COPY");
        opNames.put(PcodeOp.LOAD, "LOAD");
        opNames.put(PcodeOp.STORE, "STORE");
        opNames.put(PcodeOp.BRANCH, "BRANCH");
        opNames.put(PcodeOp.CBRANCH, "CBRANCH");
        opNames.put(PcodeOp.BRANCHIND, "BRANCHIND");
        opNames.put(PcodeOp.CALL, "CALL");
        opNames.put(PcodeOp.CALLIND, "CALLIND");
        opNames.put(PcodeOp.CALLOTHER, "CALLOTHER");
        opNames.put(PcodeOp.RETURN, "RETURN");
        opNames.put(PcodeOp.INT_EQUAL, "INT_EQUAL");
        opNames.put(PcodeOp.INT_NOTEQUAL, "INT_NOTEQUAL");
        opNames.put(PcodeOp.INT_SLESS, "INT_SLESS");
        opNames.put(PcodeOp.INT_SLESSEQUAL, "INT_SLESSEQUAL");
        opNames.put(PcodeOp.INT_LESS, "INT_LESS");
        opNames.put(PcodeOp.INT_LESSEQUAL, "INT_LESSEQUAL");
        opNames.put(PcodeOp.INT_ZEXT, "INT_ZEXT");
        opNames.put(PcodeOp.INT_SEXT, "INT_SEXT");
        opNames.put(PcodeOp.INT_ADD, "INT_ADD");
        opNames.put(PcodeOp.INT_SUB, "INT_SUB");
        opNames.put(PcodeOp.INT_CARRY, "INT_CARRY");
        opNames.put(PcodeOp.INT_SCARRY, "INT_SCARRY");
        opNames.put(PcodeOp.INT_SBORROW, "INT_SBORROW");
        opNames.put(PcodeOp.INT_2COMP, "INT_2COMP");
        opNames.put(PcodeOp.INT_NEGATE, "INT_NEGATE");
        opNames.put(PcodeOp.INT_XOR, "INT_XOR");
        opNames.put(PcodeOp.INT_AND, "INT_AND");
        opNames.put(PcodeOp.INT_OR, "INT_OR");
        opNames.put(PcodeOp.INT_LEFT, "INT_LEFT");
        opNames.put(PcodeOp.INT_RIGHT, "INT_RIGHT");
        opNames.put(PcodeOp.INT_SRIGHT, "INT_SRIGHT");
        opNames.put(PcodeOp.INT_MULT, "INT_MULT");
        opNames.put(PcodeOp.INT_DIV, "INT_DIV");
        opNames.put(PcodeOp.INT_SDIV, "INT_SDIV");
        opNames.put(PcodeOp.INT_REM, "INT_REM");
        opNames.put(PcodeOp.INT_SREM, "INT_SREM");
        opNames.put(PcodeOp.BOOL_NEGATE, "BOOL_NEGATE");
        opNames.put(PcodeOp.BOOL_XOR, "BOOL_XOR");
        opNames.put(PcodeOp.BOOL_AND, "BOOL_AND");
        opNames.put(PcodeOp.BOOL_OR, "BOOL_OR");
        opNames.put(PcodeOp.FLOAT_EQUAL, "FLOAT_EQUAL");
        opNames.put(PcodeOp.FLOAT_NOTEQUAL, "FLOAT_NOTEQUAL");
        opNames.put(PcodeOp.FLOAT_LESS, "FLOAT_LESS");
        opNames.put(PcodeOp.FLOAT_LESSEQUAL, "FLOAT_LESSEQUAL");
        opNames.put(PcodeOp.FLOAT_NAN, "FLOAT_NAN");
        opNames.put(PcodeOp.FLOAT_ADD, "FLOAT_ADD");
        opNames.put(PcodeOp.FLOAT_DIV, "FLOAT_DIV");
        opNames.put(PcodeOp.FLOAT_MULT, "FLOAT_MULT");
        opNames.put(PcodeOp.FLOAT_SUB, "FLOAT_SUB");
        opNames.put(PcodeOp.FLOAT_NEG, "FLOAT_NEG");
        opNames.put(PcodeOp.FLOAT_ABS, "FLOAT_ABS");
        opNames.put(PcodeOp.FLOAT_SQRT, "FLOAT_SQRT");
        opNames.put(PcodeOp.FLOAT_INT2FLOAT, "FLOAT_INT2FLOAT");
        opNames.put(PcodeOp.FLOAT_FLOAT2FLOAT, "FLOAT_FLOAT2FLOAT");
        opNames.put(PcodeOp.FLOAT_TRUNC, "FLOAT_TRUNC");
        opNames.put(PcodeOp.FLOAT_CEIL, "FLOAT_CEIL");
        opNames.put(PcodeOp.FLOAT_FLOOR, "FLOAT_FLOOR");
        opNames.put(PcodeOp.FLOAT_ROUND, "FLOAT_ROUND");
        opNames.put(PcodeOp.MULTIEQUAL, "MULTIEQUAL");
        opNames.put(PcodeOp.INDIRECT, "INDIRECT");
        opNames.put(PcodeOp.PIECE, "PIECE");
        opNames.put(PcodeOp.SUBPIECE, "SUBPIECE");
        opNames.put(PcodeOp.CAST, "CAST");
        opNames.put(PcodeOp.PTRADD, "PTRADD");
        opNames.put(PcodeOp.PTRSUB, "PTRSUB");
        opNames.put(PcodeOp.SEGMENTOP, "SEGMENTOP");
        opNames.put(PcodeOp.CPOOLREF, "CPOOLREF");
        opNames.put(PcodeOp.NEW, "NEW");
        opNames.put(PcodeOp.INSERT, "INSERT");
        opNames.put(PcodeOp.EXTRACT, "EXTRACT");
        opNames.put(PcodeOp.POPCOUNT, "POPCOUNT");
        opNames.put(PcodeOp.PCODE_MAX, "PCODE_MAX");
    }
}