import { fetchSecretsAws } from "@harboor/core";

export async function save(
    filePath: string,
    opts: { awsRegion: string; awsAccessKey: string; awsAccessKeySecret: string },
) {
    await fetchSecretsAws({
        aws: {
            secretName: "prod/harboor/auth",
            credentials: {
                region: opts.awsRegion,
                accessKey: opts.awsAccessKey,
                accessKeySecret: opts.awsAccessKeySecret,
            },
        },
        dest: filePath,
    });
}
