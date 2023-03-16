// Dumps the pcode into a nested json.
// @category PCode

import java.io.IOException;
import java.io.PrintWriter;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import dumper.ProgramDumper;
import ghidra.app.script.GhidraScript;
import ghidra.util.Msg;

public class ExportLowPCodeScript extends GhidraScript {

    @Override
    public void run() throws Exception {
        // Convert the P-Code to a JSON array
        var programDumper = new ProgramDumper(currentProgram);
        var jsonObject = programDumper.toJson();

        Gson gson = new GsonBuilder().setPrettyPrinting().create();

        // Convert the JsonObject to a JSON string using Gson's toJson() method
        String jsonString = gson.toJson(jsonObject);

        // Write the JSON array to a file
        var outputFile = askFile("Export PCode", "Save PCode as JSON");
        try (var writer = new PrintWriter(outputFile)) {
            writer.println(jsonString);
        } catch (IOException e) {
            Msg.showError(this, null, "Export PCode Error", "Error writing PCode to file", e);
        }
    }
}
