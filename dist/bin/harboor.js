#!/usr/bin/env node

// src/services/cli/harboor.ts
import { Command } from "commander";
import prompts from "prompts";

// src/infra/spinner/index.ts
import ora from "ora";
function getSpinner() {
  return ora({
    color: "blue",
    prefixText: "[harboor]"
  });
}

// src/features/login/index.ts
var re = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
var questions = {
  method: {
    type: "select",
    name: "method",
    message: "Choose a sign-in method:",
    choices: [
      { title: "Email", description: `A one-time use password will be sent to your inbox.`, value: "email" },
      { title: "none", description: "", value: "none" }
    ],
    initial: 0
  },
  email: {
    type: "text",
    name: "email",
    message: `Email:`,
    validate: (v) => re.test(v) ? true : "Invalid email.",
    format: (v) => v.toLowerCase()
  },
  otp: {
    type: "text",
    name: "otp",
    message: `Enter the one-time password:`,
    validate: (v) => v.length === 6 ? true : "Invalid otp.",
    format: (v) => parseInt(v)
  }
};

// src/services/cli/harboor.ts
import * as process from "node:process";
import path3 from "node:path";

// src/features/project/index.ts
import { mkdir } from "node:fs/promises";
import path2 from "node:path";
import { customAlphabet } from "nanoid";

// src/features/workspace/index.ts
import path from "node:path";
import os from "node:os";
var workspace = {
  getPath() {
    return path.resolve(os.homedir(), ".harboor/workspace");
  }
};

// src/features/project/index.ts
var genProjectId = customAlphabet("1234567890abcdefghijklmnopqrstuvwxyz-", 10);
async function createProject(projectName) {
  const id = genProjectId();
  const workspacePath = workspace.getPath();
  const projectPath = path2.resolve(workspacePath, projectName);
  await mkdir(projectPath, { recursive: true });
}

// src/features/env/index.ts
import { fetchSecretsAws } from "@harboor/core";
async function save(filePath, opts) {
  await fetchSecretsAws({
    aws: {
      secretName: "prod/harboor/auth",
      credentials: {
        region: opts.awsRegion,
        accessKey: opts.awsAccessKey,
        accessKeySecret: opts.awsAccessKeySecret
      }
    },
    dest: filePath
  });
}

// src/services/cli/harboor.ts
var program = new Command("harboor");
program.name("harboor").description("").version("0.1.0");
program.command("login", "Login to the harboor.").action(async () => {
  const spinner = getSpinner();
  const { method } = await prompts(questions["method"]);
  if (method === "none") {
    return;
  }
  const { email } = await prompts(questions["email"]);
  spinner.start("Sending an otp to " + email + "...");
  spinner.stop();
  const { otp } = await prompts(questions["otp"]);
  spinner.start("Verifying otp...");
  spinner.stop();
});
var project = program.command("project");
project.command("create").description("Setup a new project.").action(async () => {
  const projectName = "zero";
  await createProject(projectName);
});
var env2 = program.command("env").description("Manage env vars.");
env2.command("save").description("Save environment vars to a file.").option("--aws-region <string>").option("--aws-access-key <string>").option("--aws-access-key-secret <string>").argument("<string>", "relative/absolute path to the env file").action(async (inputPath, options) => {
  const _path = path3.isAbsolute(inputPath) ? inputPath : path3.resolve(process.cwd(), inputPath);
  await save(_path, {
    awsRegion: options.awsRegion ?? process.env.AWS_REGION,
    awsAccessKey: options.awsAccessKey ?? process.env.AWS_ACCESS_KEY,
    awsAccessKeySecret: options.awsAccessKeySecret ?? process.env.AWS_SECRET
  });
});
env2.command("inject").description("Inject environment vars to the current process.");
program.parse(process.argv);
