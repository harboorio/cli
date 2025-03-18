import { mkdir } from "node:fs/promises";
import path from "node:path";
import { customAlphabet } from "nanoid";
import { workspace } from "@features/workspace/index";

const genProjectId = customAlphabet("1234567890abcdefghijklmnopqrstuvwxyz-", 10);

export async function createProject(projectName: string) {
    const id = genProjectId();
    const workspacePath = workspace.getPath();
    const projectPath = path.resolve(workspacePath, projectName);
    await mkdir(projectPath, { recursive: true });
}
