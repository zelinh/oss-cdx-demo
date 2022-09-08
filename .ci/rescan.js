const { runPendingRescans } = require("../lib/vulnerabilities");
const run = async () => {
    await runPendingRescans();
};

run().catch(console.error);