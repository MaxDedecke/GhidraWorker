// GhidraWorker export script.
//
// Runs as a headless post-script (analyzeHeadless ... -postScript GhidraWorkerExport.java <outDir>)
// and dumps everything GhidraWorker needs to manage a reverse-engineering / rebuild project:
//
//   program.json    general program information (format, architecture, hashes, entry points)
//   sections.json   memory blocks
//   functions.json  all functions incl. signature, call graph and decompiler status
//   imports.json    imported symbols grouped by library
//   exports.json    exported symbols
//   strings.json    defined strings incl. referencing functions
//   globals.json    labelled global data
//   types.h         C definitions of all data types used by the program
//   decompiled/     one .c file per function (decompiler output)
//   disassembly/    one .asm file per function
//
// Progress is reported on stdout as lines "GW_PROGRESS <stage> <done> <total>" which the
// GhidraWorker job runner parses.
//
//@category GhidraWorker
//@runtime Java

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

import com.google.gson.stream.JsonWriter;

import ghidra.app.decompiler.*;
import ghidra.app.decompiler.parallel.*;
import ghidra.app.script.GhidraScript;
import ghidra.framework.Application;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.program.util.DefinedStringIterator;
import ghidra.util.task.TaskMonitor;

public class GhidraWorkerExport extends GhidraScript {

	private static final String FID_BOOKMARK_CATEGORY = "Function ID Analyzer";
	private static final int DECOMPILE_TIMEOUT_SECS = 90;
	private static final int MAX_STRINGS = 200000;
	private static final int MAX_GLOBALS = 100000;
	private static final int MAX_REF_FUNCS = 25;

	private File outDir;

	private static class DecompResult {
		String address;
		boolean ok;
		String error;
		String signature;
		int lines;
	}

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		if (args.length < 1) {
			printerr("Usage: GhidraWorkerExport.java <outputDirectory>");
			return;
		}
		outDir = new File(args[0]);
		outDir.mkdirs();

		progress("export", 0, 8);
		writeProgram();
		progress("export", 1, 8);
		writeSections();
		progress("export", 2, 8);
		writeImportsExports();
		progress("export", 3, 8);
		writeStrings();
		progress("export", 4, 8);
		writeGlobals();
		progress("export", 5, 8);
		writeTypes();
		progress("export", 6, 8);
		writeDisassembly();
		progress("export", 7, 8);
		Map<String, DecompResult> decomp = decompileAll();
		writeFunctions(decomp);
		progress("export", 8, 8);
		println("GW_DONE");
	}

	// ------------------------------------------------------------------ helpers

	private void progress(String stage, long done, long total) {
		// Use System.out directly so that the line is not decorated with the script name
		System.out.println("GW_PROGRESS " + stage + " " + done + " " + total);
		System.out.flush();
	}

	private JsonWriter json(String name) throws IOException {
		Writer w = new BufferedWriter(new OutputStreamWriter(
			new FileOutputStream(new File(outDir, name)), StandardCharsets.UTF_8));
		JsonWriter jw = new JsonWriter(w);
		jw.setIndent(" ");
		jw.setSerializeNulls(true);
		return jw;
	}

	private static String hex(Address a) {
		return a == null ? null : a.toString();
	}

	private static String fileKey(Address a) {
		return a.toString().replace(':', '_');
	}

	private boolean isLibraryFunction(Function f) {
		Bookmark bm = currentProgram.getBookmarkManager()
				.getBookmark(f.getEntryPoint(), BookmarkType.ANALYSIS, FID_BOOKMARK_CATEGORY);
		return bm != null;
	}

	private String functionNameAt(Address a) {
		Function f = currentProgram.getFunctionManager().getFunctionContaining(a);
		return f == null ? null : f.getName(true);
	}

	// ------------------------------------------------------------------ program

	private void writeProgram() throws Exception {
		Program p = currentProgram;
		try (JsonWriter w = json("program.json")) {
			w.beginObject();
			w.name("name").value(p.getName());
			w.name("executablePath").value(p.getExecutablePath());
			w.name("executableFormat").value(p.getExecutableFormat());
			w.name("md5").value(p.getExecutableMD5());
			w.name("sha256").value(p.getExecutableSHA256());
			w.name("language").value(p.getLanguageID().getIdAsString());
			w.name("processor").value(p.getLanguage().getProcessor().toString());
			w.name("endian").value(p.getLanguage().isBigEndian() ? "big" : "little");
			w.name("addressSize").value(p.getDefaultPointerSize() * 8);
			w.name("compilerSpec").value(p.getCompilerSpec().getCompilerSpecID().getIdAsString());
			w.name("compiler").value(p.getCompiler());
			w.name("imageBase").value(hex(p.getImageBase()));
			w.name("minAddress").value(hex(p.getMinAddress()));
			w.name("maxAddress").value(hex(p.getMaxAddress()));
			w.name("ghidraVersion").value(Application.getApplicationVersion());

			FunctionManager fm = p.getFunctionManager();
			int internal = 0, external = 0, thunks = 0, library = 0;
			for (Function f : fm.getFunctions(true)) {
				internal++;
				if (f.isThunk()) {
					thunks++;
				}
				if (isLibraryFunction(f)) {
					library++;
				}
			}
			for (Function f : fm.getExternalFunctions()) {
				external++;
			}
			w.name("functionCount").value(internal);
			w.name("externalFunctionCount").value(external);
			w.name("thunkCount").value(thunks);
			w.name("libraryFunctionCount").value(library);

			w.name("entryPoints").beginArray();
			SymbolTable st = p.getSymbolTable();
			AddressIterator it = st.getExternalEntryPointIterator();
			while (it.hasNext()) {
				Address a = it.next();
				Symbol s = st.getPrimarySymbol(a);
				w.beginObject();
				w.name("address").value(hex(a));
				w.name("name").value(s == null ? null : s.getName());
				w.endObject();
			}
			w.endArray();

			w.name("metadata").beginObject();
			Map<String, String> meta = p.getMetadata();
			for (Map.Entry<String, String> e : meta.entrySet()) {
				w.name(e.getKey()).value(e.getValue());
			}
			w.endObject();
			w.endObject();
		}
	}

	// ------------------------------------------------------------------ sections

	private void writeSections() throws Exception {
		try (JsonWriter w = json("sections.json")) {
			w.beginArray();
			for (MemoryBlock b : currentProgram.getMemory().getBlocks()) {
				w.beginObject();
				w.name("name").value(b.getName());
				w.name("start").value(hex(b.getStart()));
				w.name("end").value(hex(b.getEnd()));
				w.name("size").value(b.getSize());
				w.name("read").value(b.isRead());
				w.name("write").value(b.isWrite());
				w.name("execute").value(b.isExecute());
				w.name("initialized").value(b.isInitialized());
				w.name("comment").value(b.getComment());
				w.endObject();
			}
			w.endArray();
		}
	}

	// ------------------------------------------------------------------ imports / exports

	private void writeImportsExports() throws Exception {
		SymbolTable st = currentProgram.getSymbolTable();
		ExternalManager em = currentProgram.getExternalManager();
		ReferenceManager rm = currentProgram.getReferenceManager();

		try (JsonWriter w = json("imports.json")) {
			w.beginArray();
			SymbolIterator it = st.getExternalSymbols();
			while (it.hasNext() && !monitor.isCancelled()) {
				Symbol s = it.next();
				ExternalLocation loc = em.getExternalLocation(s);
				if (loc == null) {
					continue;
				}
				Set<String> users = new TreeSet<>();
				int refCount = 0;
				for (Reference r : rm.getReferencesTo(s.getAddress())) {
					refCount++;
					if (users.size() < MAX_REF_FUNCS) {
						String fn = functionNameAt(r.getFromAddress());
						if (fn != null) {
							users.add(fn);
						}
					}
				}
				// thunks / pointers referencing the import
				Function ef = loc.getFunction();
				if (ef != null) {
					for (Function thunk : thunksOf(ef)) {
						for (Reference r : rm.getReferencesTo(thunk.getEntryPoint())) {
							refCount++;
							if (users.size() < MAX_REF_FUNCS) {
								String fn = functionNameAt(r.getFromAddress());
								if (fn != null) {
									users.add(fn);
								}
							}
						}
					}
				}
				w.beginObject();
				w.name("library").value(loc.getLibraryName());
				w.name("name").value(loc.getLabel());
				w.name("originalName").value(loc.getOriginalImportedName());
				w.name("address").value(hex(loc.getAddress()));
				w.name("signature").value(ef == null ? null : ef.getPrototypeString(false, false));
				w.name("refCount").value(refCount);
				w.name("usedBy").beginArray();
				for (String u : users) {
					w.value(u);
				}
				w.endArray();
				w.endObject();
			}
			w.endArray();
		}

		try (JsonWriter w = json("exports.json")) {
			w.beginArray();
			AddressIterator it = st.getExternalEntryPointIterator();
			while (it.hasNext()) {
				Address a = it.next();
				for (Symbol s : st.getSymbols(a)) {
					w.beginObject();
					w.name("name").value(s.getName());
					w.name("address").value(hex(a));
					w.name("type").value(s.getSymbolType().toString());
					w.endObject();
				}
			}
			w.endArray();
		}
	}

	private List<Function> thunksOf(Function f) {
		List<Function> result = new ArrayList<>();
		Address[] thunkAddrs = f.getFunctionThunkAddresses(true);
		if (thunkAddrs != null) {
			for (Address a : thunkAddrs) {
				Function t = currentProgram.getFunctionManager().getFunctionAt(a);
				if (t != null) {
					result.add(t);
				}
			}
		}
		return result;
	}

	// ------------------------------------------------------------------ strings

	private void writeStrings() throws Exception {
		ReferenceManager rm = currentProgram.getReferenceManager();
		try (JsonWriter w = json("strings.json")) {
			w.beginArray();
			int count = 0;
			for (Data d : DefinedStringIterator.forProgram(currentProgram)) {
				if (monitor.isCancelled() || count >= MAX_STRINGS) {
					break;
				}
				StringDataInstance sdi = StringDataInstance.getStringDataInstance(d);
				String value = sdi.getStringValue();
				if (value == null) {
					continue;
				}
				Set<String> users = new TreeSet<>();
				int refCount = 0;
				for (Reference r : rm.getReferencesTo(d.getAddress())) {
					refCount++;
					if (users.size() < MAX_REF_FUNCS) {
						String fn = functionNameAt(r.getFromAddress());
						if (fn != null) {
							users.add(fn);
						}
					}
				}
				w.beginObject();
				w.name("address").value(hex(d.getAddress()));
				w.name("value").value(value);
				w.name("type").value(d.getDataType().getName());
				w.name("length").value(d.getLength());
				w.name("refCount").value(refCount);
				w.name("usedBy").beginArray();
				for (String u : users) {
					w.value(u);
				}
				w.endArray();
				w.endObject();
				count++;
			}
			w.endArray();
		}
	}

	// ------------------------------------------------------------------ globals

	private void writeGlobals() throws Exception {
		Listing listing = currentProgram.getListing();
		try (JsonWriter w = json("globals.json")) {
			w.beginArray();
			int count = 0;
			DataIterator it = listing.getDefinedData(true);
			while (it.hasNext() && count < MAX_GLOBALS && !monitor.isCancelled()) {
				Data d = it.next();
				Symbol s = d.getPrimarySymbol();
				if (s == null || d.hasStringValue()) {
					continue;
				}
				w.beginObject();
				w.name("address").value(hex(d.getAddress()));
				w.name("name").value(s.getName(true));
				w.name("dataType").value(d.getDataType().getDisplayName());
				w.name("length").value(d.getLength());
				w.name("source").value(s.getSource().toString());
				w.name("block").value(blockName(d.getAddress()));
				w.endObject();
				count++;
			}
			w.endArray();
		}
	}

	private String blockName(Address a) {
		MemoryBlock b = currentProgram.getMemory().getBlock(a);
		return b == null ? null : b.getName();
	}

	// ------------------------------------------------------------------ types

	private void writeTypes() throws Exception {
		File f = new File(outDir, "types.h");
		try (Writer out = new BufferedWriter(
			new OutputStreamWriter(new FileOutputStream(f), StandardCharsets.UTF_8))) {
			out.write("/* Data types recovered by Ghidra for " + currentProgram.getName() +
				" (generated by GhidraWorker) */\n\n");
			DataTypeManager dtm = currentProgram.getDataTypeManager();
			try {
				DataTypeWriter dtw = new DataTypeWriter(dtm, out);
				List<DataType> types = new ArrayList<>();
				Iterator<DataType> it = dtm.getAllDataTypes();
				while (it.hasNext()) {
					DataType dt = it.next();
					// built-ins and plain pointers/arrays are emitted on demand by DataTypeWriter
					if (dt instanceof BuiltInDataType || dt instanceof Pointer || dt instanceof Array) {
						continue;
					}
					types.add(dt);
				}
				dtw.write(types, TaskMonitor.DUMMY);
			}
			catch (Exception e) {
				out.write("\n/* type export failed: " + e + " */\n");
			}
		}
	}

	// ------------------------------------------------------------------ disassembly

	private void writeDisassembly() throws Exception {
		File dir = new File(outDir, "disassembly");
		dir.mkdirs();
		Listing listing = currentProgram.getListing();
		FunctionManager fm = currentProgram.getFunctionManager();
		int total = 0;
		for (Function f : fm.getFunctions(true)) {
			total++;
		}
		int done = 0;
		for (Function f : fm.getFunctions(true)) {
			if (monitor.isCancelled()) {
				break;
			}
			File file = new File(dir, fileKey(f.getEntryPoint()) + ".asm");
			try (Writer out = new BufferedWriter(
				new OutputStreamWriter(new FileOutputStream(file), StandardCharsets.UTF_8))) {
				out.write("; " + f.getPrototypeString(false, false) + "\n");
				out.write("; entry " + f.getEntryPoint() + ", body " + f.getBody().getMinAddress() +
					" - " + f.getBody().getMaxAddress() + "\n\n");
				InstructionIterator ii = listing.getInstructions(f.getBody(), true);
				while (ii.hasNext()) {
					Instruction ins = ii.next();
					Symbol label = ins.getPrimarySymbol();
					if (label != null && !ins.getAddress().equals(f.getEntryPoint())) {
						out.write(label.getName() + ":\n");
					}
					StringBuilder bytes = new StringBuilder();
					try {
						for (byte b : ins.getBytes()) {
							bytes.append(String.format("%02x", b & 0xff));
						}
					}
					catch (Exception e) {
						bytes.append("??");
					}
					out.write(String.format("  %s  %-20s %s\n", ins.getAddress(), bytes, ins));
				}
			}
			done++;
			if (done % 200 == 0) {
				progress("disassembly", done, total);
			}
		}
		progress("disassembly", done, total);
	}

	// ------------------------------------------------------------------ decompiler

	private Map<String, DecompResult> decompileAll() throws Exception {
		File dir = new File(outDir, "decompiled");
		dir.mkdirs();
		FunctionManager fm = currentProgram.getFunctionManager();
		List<Function> functions = new ArrayList<>();
		for (Function f : fm.getFunctions(true)) {
			if (!f.isExternal()) {
				functions.add(f);
			}
		}
		final int total = functions.size();
		final AtomicInteger done = new AtomicInteger();
		final Map<String, DecompResult> results = new ConcurrentHashMap<>();
		progress("decompile", 0, total);

		DecompileConfigurer configurer = ifc -> {
			DecompileOptions opts = new DecompileOptions();
			opts.grabFromProgram(currentProgram);
			ifc.setOptions(opts);
			ifc.toggleCCode(true);
			ifc.toggleSyntaxTree(true);
			ifc.setSimplificationStyle("decompile");
		};

		DecompilerCallback<DecompResult> callback =
			new DecompilerCallback<DecompResult>(currentProgram, configurer) {
				@Override
				public DecompResult process(DecompileResults res, TaskMonitor m) throws Exception {
					Function f = res.getFunction();
					DecompResult r = new DecompResult();
					r.address = hex(f.getEntryPoint());
					String code;
					if (res.decompileCompleted() && res.getDecompiledFunction() != null) {
						r.ok = true;
						code = res.getDecompiledFunction().getC();
						r.signature = res.getDecompiledFunction().getSignature();
					}
					else {
						r.ok = false;
						r.error = res.getErrorMessage();
						code = "/* Decompilation of " + f.getName(true) + " failed: " +
							(r.error == null ? "unknown error" : r.error.trim()) + " */\n";
					}
					r.lines = code.split("\n", -1).length;
					File file = new File(dir, fileKey(f.getEntryPoint()) + ".c");
					Files.write(file.toPath(), code.getBytes(StandardCharsets.UTF_8));
					return r;
				}
			};
		callback.setTimeout(DECOMPILE_TIMEOUT_SECS);

		try {
			ParallelDecompiler.decompileFunctions(callback, currentProgram, functions.iterator(),
				r -> {
					if (r != null) {
						results.put(r.address, r);
					}
					int d = done.incrementAndGet();
					if (d % 25 == 0 || d == total) {
						progress("decompile", d, total);
					}
				}, monitor);
		}
		finally {
			callback.dispose();
		}
		progress("decompile", total, total);
		return results;
	}

	// ------------------------------------------------------------------ functions

	private void writeFunctions(Map<String, DecompResult> decomp) throws Exception {
		FunctionManager fm = currentProgram.getFunctionManager();
		try (JsonWriter w = json("functions.json")) {
			w.beginArray();
			for (Function f : fm.getFunctions(true)) {
				if (monitor.isCancelled()) {
					break;
				}
				String addr = hex(f.getEntryPoint());
				DecompResult dr = decomp.get(addr);
				w.beginObject();
				w.name("address").value(addr);
				w.name("file").value(fileKey(f.getEntryPoint()));
				w.name("name").value(f.getName());
				w.name("fullName").value(f.getName(true));
				w.name("namespace").value(f.getParentNamespace().getName(true));
				w.name("signature").value(f.getPrototypeString(false, false));
				// C declaration as printed by the decompiler (valid C, matches the .c file)
				w.name("cSignature").value(dr == null ? null : dr.signature);
				w.name("callingConvention").value(f.getCallingConventionName());
				w.name("returnType").value(f.getReturnType().getDisplayName());
				w.name("paramCount").value(f.getParameterCount());
				w.name("size").value(f.getBody().getNumAddresses());
				w.name("thunk").value(f.isThunk());
				Function thunked = f.isThunk() ? f.getThunkedFunction(true) : null;
				w.name("thunkTarget").value(thunked == null ? null : thunked.getName(true));
				w.name("thunkTargetExternal").value(thunked != null && thunked.isExternal());
				w.name("library").value(isLibraryFunction(f));
				w.name("nameSource").value(f.getSymbol().getSource().toString());
				w.name("decompiled").value(dr != null && dr.ok);
				w.name("decompileError").value(dr == null ? "not decompiled" : dr.error);
				w.name("lines").value(dr == null ? 0 : dr.lines);

				w.name("callers").beginArray();
				for (Function c : sorted(f.getCallingFunctions(monitor))) {
					w.value(hex(c.getEntryPoint()));
				}
				w.endArray();

				w.name("callees").beginArray();
				for (Function c : sorted(f.getCalledFunctions(monitor))) {
					if (c.isExternal()) {
						continue;
					}
					w.value(hex(c.getEntryPoint()));
				}
				w.endArray();

				w.name("externalCalls").beginArray();
				for (Function c : sorted(f.getCalledFunctions(monitor))) {
					if (c.isExternal()) {
						ExternalLocation loc = c.getExternalLocation();
						w.value((loc == null ? "?" : loc.getLibraryName()) + "::" + c.getName());
					}
				}
				w.endArray();
				w.endObject();
			}
			w.endArray();
		}
	}

	private static List<Function> sorted(Set<Function> fs) {
		List<Function> l = new ArrayList<>(fs);
		l.sort(Comparator.comparing(Function::getEntryPoint));
		return l;
	}
}
