const { cache } = require("./util");
const OpenSearch = require("../opensearch");
const WorkerPool = require("../worker_pool");
const path = require("path");
const os = require("os");
const numThreads = os.cpus().length;

const fetch = async () => {
    const sources = ['CVEProject', 'CloudSecurityAlliance', 'GitLabAdvisory', 'GitHubAdvisory'];
    const artifacts = [];
    return new Promise(resolve => {
        const numSources = sources.length;
        let numPending = numSources;
        const pool = new WorkerPool(path.join(__dirname, 'worker.js'), numThreads);
        for (let i = 0; i < numSources; i++) {
            // Add a delay between invocations to avoid install conflicts
            setTimeout(() => {
                pool.runTask(
                    sources[i],
                    (err, result) => {
                        if (err) {
                            console.error(`${sources[i]} failed:`, err);
                        }
                        if (result && result !== 'done') console.log(result);
                        if (--numPending <= 0) {
                            pool.close();
                            resolve(artifacts);
                        }
                    },
                    data => {
                        if (data?.artifactsDir) artifacts.push(data.artifactsDir);
                    }
                );
            }, 10000 * i);

        }
    });
}

const run = async () => {
    console.log('Advisory cataloging started');

    const cacheDirs = await fetch();
    console.log('Advisory caching completed');

    const list = [];
    let counter = 0;
    const indexName = `advisories-${Date.now()}`;
    const save = async (record, force = false) => {
        if (record) list.push(record);

        const listLength = list.length;
        if (force || listLength > 999) {
            await OpenSearch.indexDocs(indexName, list.splice(0, listLength));
            counter += listLength;
        }
    };

    console.log('Indexing advisories...');
    await cache.finalize(cacheDirs, save);
    await OpenSearch.pointAlias('advisories', indexName, true);

    console.log('Advisory cataloging completed');
};

module.exports = {
    run
}