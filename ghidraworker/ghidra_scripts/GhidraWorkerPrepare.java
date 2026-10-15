// GhidraWorker pre-script: tunes auto-analysis options before analysis starts.
//
// Usage: analyzeHeadless ... -preScript GhidraWorkerPrepare.java [thorough]
//
// "thorough" enables the slower analyzers that noticeably improve function signatures and
// therefore the quality of the decompiled code that the rebuild is based on.
//
//@category GhidraWorker
//@runtime Java

import java.util.Map;

import ghidra.app.script.GhidraScript;

public class GhidraWorkerPrepare extends GhidraScript {

	@Override
	protected void run() throws Exception {
		boolean thorough = false;
		for (String a : getScriptArgs()) {
			if ("thorough".equalsIgnoreCase(a)) {
				thorough = true;
			}
		}
		Map<String, String> options = getCurrentAnalysisOptionsAndValues(currentProgram);
		if (thorough) {
			enable(options, "Decompiler Parameter ID");
			enable(options, "Aggressive Instruction Finder");
		}
		println("GW_PREPARE thorough=" + thorough);
	}

	private void enable(Map<String, String> options, String name) {
		if (options.containsKey(name)) {
			setAnalysisOption(currentProgram, name, "true");
			println("GW_PREPARE enabled " + name);
		}
	}
}
