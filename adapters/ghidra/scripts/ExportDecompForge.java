// Exporta el programa actual de Ghidra como documento DecompForge `re-1.0`.
//
// Uso en la GUI: Tools > DecompForge > Exportar re-1.0 (pide el fichero de salida).
// Uso en modo headless:
//   analyzeHeadless <proyecto> <nombre> -process <programa> \
//     -postScript ExportDecompForge.java /ruta/export.json
//
// Incluye funciones, instrucciones, comentarios, referencias cruzadas y tipos
// definidos por el usuario. No modifica el programa.
//@category DecompForge
//@menupath Tools.DecompForge.Exportar re-1.0
//@keybinding

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Enum;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.Union;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;

public class ExportDecompForge extends GhidraScript {

    private static final String SCHEMA_VERSION = "re-1.0";

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            printerr("uso: ExportDecompForge.java <salida.json>");
            return;
        }
        File output = new File(args[0]);
        Program program = currentProgram;

        JsonObject root = new JsonObject();
        root.addProperty("schema_version", SCHEMA_VERSION);
        root.addProperty("kind", "export");
        root.add("source", source(program));
        root.add("project", project(program));
        root.add("functions", functions(program));
        root.add("xrefs", xrefs(program));
        root.add("types", types(program));

        Gson gson = new GsonBuilder()
            .setPrettyPrinting()
            .disableHtmlEscaping()
            .create();
        File parent = output.getAbsoluteFile().getParentFile();
        if (parent != null) {
            parent.mkdirs();
        }
        try (Writer writer = new OutputStreamWriter(
                new FileOutputStream(output), StandardCharsets.UTF_8)) {
            writer.write(gson.toJson(root));
            writer.write("\n");
        }
        println("DecompForge: exportado " + output.getAbsolutePath());
    }

    private JsonObject source(Program program) {
        JsonObject source = new JsonObject();
        source.addProperty("tool", "ghidra");
        String version = "desconocida";
        try {
            version = ghidra.framework.Application.getApplicationVersion();
        } catch (Throwable ignored) {
            // En algunos entornos headless la versión no está disponible.
        }
        source.addProperty("version", version);
        source.addProperty("program", program.getName());
        return source;
    }

    private JsonObject project(Program program) {
        JsonObject project = new JsonObject();
        project.addProperty("name", program.getName());
        project.addProperty("arch", architecture(program));
        project.addProperty("endian", program.getLanguage().isBigEndian() ? "big" : "little");
        project.addProperty("bits", program.getAddressFactory().getDefaultAddressSpace().getSize());
        Address entry = entryPoint(program);
        if (entry != null) {
            project.addProperty("entry", address(entry));
        }
        return project;
    }

    private String architecture(Program program) {
        String processor = program.getLanguage().getProcessor().toString().toLowerCase();
        int bits = program.getAddressFactory().getDefaultAddressSpace().getSize();
        if (processor.contains("mips")) {
            return "mips";
        }
        if (processor.contains("powerpc") || processor.contains("ppc")) {
            return "ppc";
        }
        if (processor.contains("aarch64") || processor.contains("arm64")) {
            return "arm64";
        }
        if (processor.contains("arm")) {
            return "arm";
        }
        if (processor.contains("spu")) {
            return "spu";
        }
        if (processor.contains("x86")) {
            return bits == 64 ? "x86_64" : "x86";
        }
        return "unknown";
    }

    private Address entryPoint(Program program) {
        SymbolTable symbols = program.getSymbolTable();
        Address entry = null;
        AddressIterator iterator = symbols.getExternalEntryPointIterator();
        while (iterator.hasNext()) {
            Address candidate = iterator.next();
            if (entry == null || candidate.compareTo(entry) < 0) {
                entry = candidate;
            }
        }
        return entry;
    }

    private JsonArray functions(Program program) {
        List<Function> ordered = new ArrayList<>();
        FunctionIterator iterator = program.getFunctionManager().getFunctions(true);
        while (iterator.hasNext()) {
            ordered.add(iterator.next());
        }
        ordered.sort(Comparator.comparingLong(f -> f.getEntryPoint().getOffset()));

        JsonArray array = new JsonArray();
        for (Function function : ordered) {
            array.add(function(program, function));
        }
        return array;
    }

    private JsonObject function(Program program, Function function) {
        JsonObject json = new JsonObject();
        json.addProperty("address", address(function.getEntryPoint()));
        json.addProperty("name", function.getName());
        String signature = function.getPrototypeString(false, false);
        if (signature != null && !signature.isBlank()) {
            json.addProperty("signature", signature.replace('\n', ' ').replace('\r', ' '));
        }
        long size = function.getBody().getNumAddresses();
        if (size >= 0) {
            json.addProperty("size", size);
        }

        Map<String, JsonObject> comments = new LinkedHashMap<>();
        if (function.getComment() != null && !function.getComment().isBlank()) {
            addComment(comments, function.getEntryPoint(), function.getComment());
        }
        JsonArray instructions = instructions(program, function, comments);
        if (instructions.size() > 0) {
            json.add("instructions", instructions);
        }
        if (!comments.isEmpty()) {
            JsonArray array = new JsonArray();
            for (JsonObject comment : comments.values()) {
                array.add(comment);
            }
            json.add("comments", array);
        }
        return json;
    }

    private JsonArray instructions(
            Program program, Function function, Map<String, JsonObject> comments) {
        JsonArray array = new JsonArray();
        Listing listing = program.getListing();
        InstructionIterator iterator = listing.getInstructions(function.getBody(), true);
        while (iterator.hasNext()) {
            Instruction instruction = iterator.next();
            JsonObject json = new JsonObject();
            json.addProperty("address", address(instruction.getAddress()));
            String bytes = bytes(instruction);
            if (bytes != null) {
                json.addProperty("bytes", bytes);
            }
            String mnemonic = instruction.getMnemonicString();
            json.addProperty("mnemonic", mnemonic);
            String operands = operands(instruction);
            if (!operands.isEmpty()) {
                json.addProperty("operands", operands);
            }

            String eol = instruction.getComment(CommentType.EOL);
            String pre = instruction.getComment(CommentType.PRE);
            String post = instruction.getComment(CommentType.POST);
            String chosen = firstNonBlank(eol, pre, post);
            if (chosen != null) {
                json.addProperty("comment", chosen);
                addComment(comments, instruction.getAddress(), chosen);
            }
            array.add(json);
        }
        return array;
    }

    private static String operands(Instruction instruction) {
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < instruction.getNumOperands(); i++) {
            String representation = instruction.getDefaultOperandRepresentation(i);
            if (representation == null || representation.isBlank()) {
                continue;
            }
            if (result.length() > 0) {
                result.append(", ");
            }
            result.append(representation.trim());
        }
        return result.toString();
    }

    private static String firstNonBlank(String... values) {
        for (String value : values) {
            if (value != null && !value.isBlank()) {
                return value;
            }
        }
        return null;
    }

    private static void addComment(
            Map<String, JsonObject> comments, Address address, String text) {
        String clean = text.replace("\r\n", "\n").replace('\r', '\n').trim();
        if (clean.isEmpty()) {
            return;
        }
        String key = address(address) + "\u0000" + clean;
        if (comments.containsKey(key)) {
            return;
        }
        JsonObject comment = new JsonObject();
        comment.addProperty("address", address(address));
        comment.addProperty("text", clean);
        comments.put(key, comment);
    }

    private String bytes(Instruction instruction) {
        int length = instruction.getLength();
        if (length <= 0) {
            return null;
        }
        byte[] raw = new byte[length];
        try {
            int read = instruction.getBytes(raw, 0);
            if (read <= 0) {
                return null;
            }
            StringBuilder hex = new StringBuilder(read * 2);
            for (int i = 0; i < read; i++) {
                hex.append(String.format("%02x", raw[i] & 0xff));
            }
            return hex.toString();
        } catch (MemoryAccessException e) {
            return null;
        }
    }

    private JsonArray xrefs(Program program) {
        Address start = program.getMemory().getMinAddress();
        if (start == null) {
            return new JsonArray();
        }
        ReferenceManager manager = program.getReferenceManager();
        ReferenceIterator iterator = manager.getReferenceIterator(start);
        Set<String> seen = new LinkedHashSet<>();
        List<JsonObject> collected = new ArrayList<>();
        while (iterator.hasNext()) {
            Reference reference = iterator.next();
            Address from = reference.getFromAddress();
            Address to = reference.getToAddress();
            if (from == null || to == null) {
                continue;
            }
            String kind = kind(reference.getReferenceType());
            String key = address(from) + "|" + address(to) + "|" + kind;
            if (!seen.add(key)) {
                continue;
            }
            JsonObject json = new JsonObject();
            json.addProperty("src", address(from));
            json.addProperty("dst", address(to));
            json.addProperty("kind", kind);
            collected.add(json);
        }
        collected.sort(Comparator
            .comparing((JsonObject item) -> item.get("src").getAsString())
            .thenComparing(item -> item.get("dst").getAsString())
            .thenComparing(item -> item.get("kind").getAsString()));
        JsonArray array = new JsonArray();
        for (JsonObject item : collected) {
            array.add(item);
        }
        return array;
    }

    private static String kind(RefType type) {
        if (type == null) {
            return "ref";
        }
        if (type.isCall()) {
            return "call";
        }
        if (type.isJump()) {
            return type.isConditional() ? "cond_jump" : "jump";
        }
        if (type.isRead() && type.isWrite()) {
            return "read_write";
        }
        if (type.isRead()) {
            return "read";
        }
        if (type.isWrite()) {
            return "write";
        }
        if (type.isData()) {
            return "data";
        }
        return "ref";
    }

    private JsonArray types(Program program) {
        ProgramDataTypes types = new ProgramDataTypes(program.getDataTypeManager());
        return types.toJson();
    }

    private String address(Address address) {
        String hex = Long.toUnsignedString(address.getOffset(), 16);
        int width = hex.length() <= 8 ? 8 : 16;
        while (hex.length() < width) {
            hex = "0" + hex;
        }
        return "0x" + hex;
    }

    /** Recolector de tipos para no mezclar la lógica en `run`. */
    private static final class ProgramDataTypes {
        private final DataTypeManager manager;

        ProgramDataTypes(DataTypeManager manager) {
            this.manager = manager;
        }

        JsonArray toJson() {
            List<DataType> ordered = new ArrayList<>();
            java.util.Iterator<DataType> iterator = manager.getAllDataTypes();
            while (iterator.hasNext()) {
                DataType type = iterator.next();
                if (type == null || type.getName() == null || type.getName().isBlank()) {
                    continue;
                }
                SourceType source = type.getSource();
                if (source != SourceType.USER_DEFINED && source != SourceType.IMPORTED) {
                    continue;
                }
                ordered.add(type);
            }
            ordered.sort(Comparator.comparing(DataType::getName));

            JsonArray array = new JsonArray();
            Set<String> seen = new LinkedHashSet<>();
            for (DataType type : ordered) {
                String key = type.getName() + "|" + kind(type);
                if (!seen.add(key)) {
                    continue;
                }
                JsonObject json = new JsonObject();
                json.addProperty("name", type.getName());
                json.addProperty("kind", kind(type));
                if (type.getLength() >= 0) {
                    json.addProperty("size", type.getLength());
                }
                String description = type.getDescription();
                if (description != null && !description.isBlank()) {
                    json.addProperty("definition", description);
                }
                array.add(json);
            }
            return array;
        }

        private static String kind(DataType type) {
            if (type instanceof Structure) {
                return "struct";
            }
            if (type instanceof Union) {
                return "union";
            }
            if (type instanceof Enum) {
                return "enum";
            }
            if (type instanceof TypeDef) {
                return "typedef";
            }
            if (type instanceof FunctionDefinition) {
                return "function";
            }
            if (type instanceof Pointer) {
                return "pointer";
            }
            if (type instanceof Array) {
                return "array";
            }
            return "other";
        }
    }
}
