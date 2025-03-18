import { type PromptObject } from "prompts";

const re =
    /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;

export const questions: Record<string, PromptObject<string> | PromptObject<string>[]> = {
    method: {
        type: "select" as const,
        name: "method",
        message: "Choose a sign-in method:",
        choices: [
            { title: "Email", description: `A one-time use password will be sent to your inbox.`, value: "email" },
            { title: "none", description: "", value: "none" },
        ],
        initial: 0,
    },
    email: {
        type: "text" as const,
        name: "email",
        message: `Email:`,
        validate: (v) => (re.test(v) ? true : "Invalid email."),
        format: (v) => v.toLowerCase(),
    },
    otp: {
        type: "text" as const,
        name: "otp",
        message: `Enter the one-time password:`,
        validate: (v) => (v.length === 6 ? true : "Invalid otp."),
        format: (v) => parseInt(v),
    },
};
