import path from "node:path";
import os from "node:os";

export const workspace = {
    getPath() {
        return path.resolve(os.homedir(), ".harboor/workspace");
    },
};
