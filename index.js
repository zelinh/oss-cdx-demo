const SBOM = require('./lib/sbom');
const Advisories = require('./lib/advisories');
const Vulnerabilities = require('./lib/vulnerabilities');
const OpenSearch = require("./lib/opensearch");
const Summary = require("./lib/summary");

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
    if (args.includes('--email')) {
        await Summary.email();
    }
};


run().catch(err => {
    console.error(err.message || err);
    console.log(err.stack);

    process.exit(1);
});