//Dumps the pcode into a nested json.
//@category PCode

import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;

import ghidra.app.script.GhidraScript;
import ghidra.util.Msg;
import utils.ProgramDump;

public class ExportPCodeToJsonScript extends GhidraScript {

    @Override
    public void run() throws Exception {
        // Convert the P-Code to a JSON array
        var dump = new ProgramDump(currentProgram);
        var jObj = dump.toJson();

        // Write the JSON array to a file
        File outputFile = askFile("Export PCode", "Save PCode as JSON");
        try (PrintWriter writer = new PrintWriter(outputFile)) {
            writer.println(jObj.toString());
        } catch (IOException e) {
            Msg.showError(this, null, "Export PCode Error", "Error writing PCode to file", e);
        }
    }
}
