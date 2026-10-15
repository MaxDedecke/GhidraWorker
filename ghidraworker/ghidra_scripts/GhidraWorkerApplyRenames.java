// GhidraWorker: applies function renames made in the GhidraWorker UI to the Ghidra program.
//
// Usage: analyzeHeadless ... -process <program> -postScript GhidraWorkerApplyRenames.java <renames.json>
//
// renames.json is a JSON object { "<entry address>": "<new name>", ... }.
// Renames are applied as USER_DEFINED symbols so they survive re-analysis and show up in the
// Ghidra GUI as well as in every following GhidraWorker export.
//
//@category GhidraWorker
//@runtime Java

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;

public class GhidraWorkerApplyRenames extends GhidraScript {

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		if (args.length < 1) {
			printerr("Usage: GhidraWorkerApplyRenames.java <renames.json>");
			return;
		}
		JsonObject renames;
		try (Reader r = new InputStreamReader(new FileInputStream(args[0]), StandardCharsets.UTF_8)) {
			renames = JsonParser.parseReader(r).getAsJsonObject();
		}
		int applied = 0, failed = 0;
		for (Map.Entry<String, JsonElement> e : renames.entrySet()) {
			Address addr = currentProgram.getAddressFactory().getAddress(e.getKey());
			Function f = addr == null ? null : getFunctionAt(addr);
			String newName = e.getValue().getAsString().trim();
			if (f == null || newName.isEmpty()) {
				printerr("GW_RENAME_FAILED " + e.getKey() + " (no function)");
				failed++;
				continue;
			}
			if (newName.equals(f.getName())) {
				continue;
			}
			try {
				f.setName(newName, SourceType.USER_DEFINED);
				applied++;
			}
			catch (Exception ex) {
				printerr("GW_RENAME_FAILED " + e.getKey() + " -> " + newName + ": " + ex.getMessage());
				failed++;
			}
		}
		println("GW_RENAMES applied=" + applied + " failed=" + failed);
	}
}
