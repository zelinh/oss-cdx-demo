const SBOM = require('./lib/sbom');
const Advisories = require('./lib/advisories');
const Vulnerabilities = require('./lib/vulnerabilities');
const OpenSearch = require("./lib/opensearch");
const normalizer = require("./lib/normalizer");

const args = process.argv;

const run = async () => {
    await OpenSearch.initIndices();
    if (args.includes('--sbom')) {
        await SBOM.run();
    }
    if (args.includes('--advs')) {
        await Advisories.run();
    }
    if (args.includes('--vuls')) {
        await Vulnerabilities.run();
    }
};


run().catch(err => {
    console.error(err.message || err);
    console.log(err.stack);

    process.exit(1);
});