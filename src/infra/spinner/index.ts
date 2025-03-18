import ora from "ora";

export function getSpinner() {
    return ora({
        color: "blue",
        prefixText: "[harboor]",
    });
}
