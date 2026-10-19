// Export analysis through the official Ghidra scripting and block APIs.
// @category ResearchPlatform
import ghidra.app.util.headless.HeadlessScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.symbol.Reference;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

/** Bounded inventory, call references and basic blocks from a headless program. */
public class ResearchExport extends HeadlessScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 2) throw new IllegalArgumentException("output and limit required");
        int limit = Integer.parseInt(args[1]);
        if (limit <= 0) throw new IllegalArgumentException("positive limit required");
        JsonObject result = new JsonObject();
        result.addProperty("backend", "ghidra");
        result.addProperty("language", currentProgram.getLanguageID().toString());
        result.addProperty("image_base", currentProgram.getImageBase().toString());
        result.addProperty("analysis_timed_out", analysisTimeoutOccurred());
        boolean truncated = analysisTimeoutOccurred();
        JsonArray functions = new JsonArray(), calls = new JsonArray();
        FunctionIterator iterator = currentProgram.getFunctionManager().getFunctions(true);
        while (iterator.hasNext()) {
            monitor.checkCancelled();
            if (functions.size() >= limit) { truncated = true; break; }
            Function function = iterator.next();
            JsonObject item = new JsonObject();
            item.addProperty("name", function.getName(true));
            item.addProperty("address", function.getEntryPoint().toString());
            item.addProperty("size", function.getBody().getNumAddresses());
            item.addProperty("signature", function.getSignature().getPrototypeString());
            item.addProperty("external", function.isExternal());
            functions.add(item);
        }
        InstructionIterator instructions = currentProgram.getListing().getInstructions(true);
        int scanned = 0;
        while (instructions.hasNext()) {
            monitor.checkCancelled();
            if (++scanned > limit || calls.size() >= limit) { truncated = true; break; }
            Instruction instruction = instructions.next();
            if (!instruction.getFlowType().isCall()) continue;
            boolean resolved = false;
            for (Reference reference : instruction.getReferencesFrom()) {
                if (!reference.getReferenceType().isCall()) continue;
                if (calls.size() >= limit) { truncated = true; break; }
                JsonObject edge = new JsonObject();
                Function caller = currentProgram.getFunctionManager().getFunctionContaining(instruction.getAddress());
                Function callee = currentProgram.getFunctionManager().getFunctionAt(reference.getToAddress());
                edge.addProperty("site", instruction.getAddress().toString());
                edge.addProperty("caller", caller == null ? instruction.getAddress().toString() : caller.getName(true));
                edge.addProperty("callee", callee == null ? reference.getToAddress().toString() : callee.getName(true));
                edge.addProperty("target", reference.getToAddress().toString());
                edge.addProperty("resolved", callee != null);
                calls.add(edge); resolved = true;
            }
            if (!resolved && calls.size() < limit) {
                JsonObject edge = new JsonObject();
                edge.addProperty("site", instruction.getAddress().toString());
                edge.addProperty("operands", instruction.toString());
                edge.addProperty("resolved", false); calls.add(edge);
            }
        }
        JsonArray blocks = new JsonArray(), edges = new JsonArray();
        CodeBlockIterator blockIterator = new BasicBlockModel(currentProgram).getCodeBlocks(monitor);
        while (blockIterator.hasNext()) {
            monitor.checkCancelled();
            if (blocks.size() >= limit) { truncated = true; break; }
            CodeBlock block = blockIterator.next();
            JsonObject item = new JsonObject();
            item.addProperty("start", block.getFirstStartAddress().toString());
            item.addProperty("end", block.getMaxAddress().toString());
            item.addProperty("name", block.getName()); blocks.add(item);
            CodeBlockReferenceIterator destinations = block.getDestinations(monitor);
            while (destinations.hasNext()) {
                if (edges.size() >= limit) { truncated = true; break; }
                CodeBlockReference destination = destinations.next();
                JsonObject edge = new JsonObject();
                edge.addProperty("source", block.getFirstStartAddress().toString());
                edge.addProperty("target", destination.getDestinationAddress().toString());
                edge.addProperty("kind", destination.getFlowType().toString()); edges.add(edge);
            }
        }
        JsonArray libraries = new JsonArray();
        for (String library : currentProgram.getExternalManager().getExternalLibraryNames()) libraries.add(library);
        result.add("functions", functions); result.add("calls", calls);
        result.add("blocks", blocks); result.add("edges", edges); result.add("libraries", libraries);
        result.addProperty("truncated", truncated);
        Files.writeString(Path.of(args[0]), new GsonBuilder().create().toJson(result), StandardCharsets.UTF_8);
    }
}
