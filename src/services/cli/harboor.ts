#!/usr/bin/env node

/*
 * harboor cli
 * backend development and deployment platform
 *
 * harboor project create
 * create a project record to keep a common configuration among devs
 * - creates a database record with project details
 * - create a git repository on the server
 *
 * harboor feature [feature]
 * develop or update a feature with ai assisted and automated git commits, ai generated tests and live preview
 * - makes a partial clone of the repository and creates a feature branch
 * - creates the feature directory structure under src/features/[feature]
 * - it might spawn a dev server based on a cli flag:
 *   - local dev server to serve the feature
 *   - cloud dev server to serve the feature over web with a private link
 *   - cloud dev server with simultaneous reloading of all the features to preview the whole app
 * - the server reloads the app as changes happen
 * - get notifications about the new #infra or #feature code being developed
 * - ai creates tests for the feature as it's being developed
 * - whenever the changes are valid, ai creates a commit
 *
 * harboor deploy [feature]
 *
 */

import { Command } from "commander";
import prompts from "prompts";
import { getSpinner } from "@infra/spinner/index";
import { questions } from "@features/login/index";
import * as process from "node:process";
import path from "node:path";
import { createProject } from "@features/project/index";
import { save } from "@features/env/index";

const program = new Command("harboor");

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

const project = program.command("project");
project
    .command("create")
    .description("Setup a new project.")
    .action(async () => {
        const projectName = "zero"; // TODO read from user prompt
        await createProject(projectName);
    });

const env = program.command("env").description("Manage env vars.");
env.command("save")
    .description("Save environment vars to a file.")
    .option("--aws-region <string>")
    .option("--aws-access-key <string>")
    .option("--aws-access-key-secret <string>")
    .argument("<string>", "relative/absolute path to the env file")
    .action(async (inputPath: string, options) => {
        const _path = path.isAbsolute(inputPath) ? inputPath : path.resolve(process.cwd(), inputPath);
        await save(_path, {
            awsRegion: options.awsRegion ?? process.env.AWS_REGION,
            awsAccessKey: options.awsAccessKey ?? process.env.AWS_ACCESS_KEY,
            awsAccessKeySecret: options.awsAccessKeySecret ?? process.env.AWS_SECRET,
        });
    });
env.command("inject").description("Inject environment vars to the current process.");

program.parse(process.argv);
