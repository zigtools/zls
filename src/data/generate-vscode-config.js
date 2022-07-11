// Run with node

const fs = require("fs");
const path = require("path");

const sourceOfTruth = fs.readFileSync(path.join(__dirname, "..", "Config.zig"));

const lines = sourceOfTruth.toString().split("\n");

function mapType(type) {
    switch (type) {
        case "?[]const u8":
            return "string";

        case "bool":
            return "boolean";

        case "usize":
            return "integer";
    
        default:
            throw new Error("unknown type!");
    }
}

let comment = null;
for (const line of lines) {
    if (line.startsWith("///")) {
        if (comment === null) comment = line.slice(3).trim();
        else comment += line.slice(3);
    } else if (comment) {
        const name = line.split(":")[0].trim();
        const type = line.split(":")[1].split("=")[0].trim();
        const defaultValue = line.split(":")[1].split("=")[1].trim().replace(",","");
        
        // console.log(name, type, defaultValue);

        console.log(`"zls.${name}": ${JSON.stringify({
            "scope": "resource",
            "type": mapType(type),
            "description": comment,
            "default": JSON.parse(defaultValue)
        })},`);

        comment = null;
    }
}
