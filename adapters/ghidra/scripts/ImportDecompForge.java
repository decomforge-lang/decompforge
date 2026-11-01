// Importa un documento DecompForge `re-1.0` de tipo `updates` en Ghidra.
//
// Aplica nombres, firmas y comentarios. Todo o nada: si una sola actualización
// falla, la transacción se revierte completa.
//
// Uso en la GUI: Tools > DecompForge > Importar re-1.0 (pide el JSON).
// Uso en modo headless:
//   analyzeHeadless <proyecto> <nombre> -process <programa> -noanalysis \
//     -postScript ImportDecompForge.java /ruta/updates.json
//
//@category DecompForge
//@menupath Tools.DecompForge.Importar re-1.0
//@keybinding

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.cparser.C.CParserUtils;
import ghidra.app.util.cparser.C.ParseException;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;

public class ImportDecompForge extends GhidraScript {

    private static final String SCHEMA_VERSION = "re-1.0";

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            printerr("uso: ImportDecompForge.java <updates.json>");
            return;
        }
        File input = new File(args[0]);
        if (!input.isFile()) {
            throw new IllegalArgumentException("no existe el fichero: " + input);
        }
        String text = new String(Files.readAllBytes(input.toPath()), StandardCharsets.UTF_8);
        // Algunos editores de Windows guardan UTF-8 con BOM; no forma parte del
        // documento JSON y hay que quitarlo antes de parsear.
        if (!text.isEmpty() && text.charAt(0) == '\uFEFF') {
            text = text.substring(1);
        }
        JsonObject root = JsonParser.parseString(text).getAsJsonObject();
        checkDocument(root);

        Program program = currentProgram;
        int names = 0;
        int signatures = 0;
        int comments = 0;
        int created = 0;
        List<String> failures = new ArrayList<>();

        int transaction = program.startTransaction("DecompForge: importar updates re-1.0");
        boolean committed = false;
        try {
            JsonArray functions = root.getAsJsonArray("functions");
            for (JsonElement element : functions) {
                JsonObject update = element.getAsJsonObject();
                Address address;
                try {
                    address = parseAddress(program, requiredString(update, "address"));
                } catch (RuntimeException e) {
                    failures.add(e.getMessage());
                    continue;
                }

                Function function = program.getFunctionManager().getFunctionAt(address);
                if (function == null) {
                    function = createFunction(address, optionalString(update, "name"));
                    if (function == null) {
                        failures.add("no se pudo crear una funcion en " + textAddress(address));
                        continue;
                    }
                    created++;
                }

                if (update.has("signature")) {
                    String signatureText = requiredString(update, "signature");
                    try {
                        FunctionDefinitionDataType signature = CParserUtils.parseSignature(
                            null, program, signatureText, false);
                        if (signature == null) {
                            failures.add(textAddress(address) + ": firma no reconocida: "
                                + signatureText);
                        } else {
                            ApplyFunctionSignatureCmd command = new ApplyFunctionSignatureCmd(
                                address, signature, SourceType.USER_DEFINED);
                            if (!command.applyTo(program, monitor)) {
                                failures.add(textAddress(address) + ": no se pudo aplicar la firma");
                            } else {
                                signatures++;
                            }
                        }
                    } catch (ParseException e) {
                        failures.add(textAddress(address) + ": firma invalida: " + e.getMessage());
                    }
                }

                if (update.has("name")) {
                    try {
                        function.setName(requiredString(update, "name"), SourceType.USER_DEFINED);
                        names++;
                    } catch (Exception e) {
                        failures.add(textAddress(address) + ": nombre invalido: " + e.getMessage());
                    }
                }

                if (update.has("comments")) {
                    for (JsonElement commentElement : update.getAsJsonArray("comments")) {
                        JsonObject comment = commentElement.getAsJsonObject();
                        String commentText = requiredString(comment, "text");
                        Address commentAddress;
                        try {
                            commentAddress = parseAddress(program,
                                requiredString(comment, "address"));
                        } catch (RuntimeException e) {
                            failures.add(e.getMessage());
                            continue;
                        }
                        if (commentAddress.equals(function.getEntryPoint())) {
                            function.setComment(commentText);
                            comments++;
                        } else {
                            CodeUnit code = program.getListing().getCodeUnitAt(commentAddress);
                            if (code == null) {
                                failures.add(textAddress(commentAddress)
                                    + ": no hay codigo ni datos para el comentario");
                            } else {
                                code.setComment(CommentType.EOL, commentText);
                                comments++;
                            }
                        }
                    }
                }
            }

            if (failures.isEmpty()) {
                committed = true;
            }
        } finally {
            program.endTransaction(transaction, committed);
        }

        if (!committed) {
            for (String failure : failures) {
                printerr("DecompForge: " + failure);
            }
            throw new RuntimeException(
                "importacion cancelada; se revirtieron todos los cambios ("
                + failures.size() + " errores)");
        }
        println("DecompForge: importado " + input.getName()
            + " (" + created + " funciones creadas, " + names + " nombres, "
            + signatures + " firmas, " + comments + " comentarios)");
    }

    private void checkDocument(JsonObject root) {
        if (!root.has("schema_version")
                || !SCHEMA_VERSION.equals(root.get("schema_version").getAsString())) {
            throw new IllegalArgumentException(
                "schema_version debe ser \"" + SCHEMA_VERSION + "\"");
        }
        if (!root.has("kind") || !"updates".equals(root.get("kind").getAsString())) {
            throw new IllegalArgumentException("kind debe ser \"updates\"");
        }
        if (!root.has("functions") || !root.get("functions").isJsonArray()) {
            throw new IllegalArgumentException("falta el array 'functions'");
        }
    }

    private Address parseAddress(Program program, String value) {
        if (value == null || !value.startsWith("0x")) {
            throw new IllegalArgumentException("direccion invalida: " + value);
        }
        try {
            long offset = Long.parseUnsignedLong(value.substring(2), 16);
            return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("direccion invalida: " + value);
        }
    }

    private static String requiredString(JsonObject object, String key) {
        if (!object.has(key) || !object.get(key).isJsonPrimitive()
                || !object.get(key).getAsJsonPrimitive().isString()) {
            throw new IllegalArgumentException("falta el campo de texto '" + key + "'");
        }
        return object.get(key).getAsString();
    }

    private static String optionalString(JsonObject object, String key) {
        return object.has(key) && !object.get(key).isJsonNull()
            ? object.get(key).getAsString()
            : null;
    }

    private static String textAddress(Address address) {
        String hex = Long.toUnsignedString(address.getOffset(), 16);
        int width = hex.length() <= 8 ? 8 : 16;
        while (hex.length() < width) {
            hex = "0" + hex;
        }
        return "0x" + hex;
    }
}
