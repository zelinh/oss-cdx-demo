const { promisify } = require('util');
const fs = require("fs-extra");
const { parentPort } = require('worker_threads');
const bom = require("@AMoo-Miki/cdxgen");
const OpenSearch = require("../opensearch");
const git = require("../git");
const normalizer = require("../normalizer");
const exec = promisify(require('child_process').exec);
const { mkdtemp } = require('fs/promises');
const path = require("path");
const os = require("os");

const run = async project => {
    const logKey = `${project.name} @ ${project.tag}`;
    console.log(`[${logKey}]\tWorking on SBOM...`);
    const indexName = normalizer.getIndexName(project);

    // Check existing index
    if (await OpenSearch.indexExists(indexName)) {
        console.log(`[${logKey}]\tSkipping #${project.hash}`);
    } else {
        // Execution timestamp
        const now = Date.now();
        const { dir } = await git.clone(project.repo, project.tag);

        const installCacheDir = await mkdtemp(path.join(os.tmpdir(), 'cache-'));

        // Install the project
        if (Array.isArray(project.install) && project.install.length) {
            for await (const cmd of project.install) {
                console.log(`[${logKey}]\tRunning:`, cmd);
                let stdout, stderr;
                try {
                    ({ stdout, stderr } = await exec(`bash -c ". $NVM_DIR/nvm.sh; ${cmd}"`, {
                        cwd: dir,
                        maxBuffer: 10 * 1024 * 1024,
                        env: {
                            ...process.env,
                            YARN_CACHE_FOLDER: installCacheDir,
                            GOPATH: installCacheDir,
                        }
                    }));
                } catch (ex) {
                    if (stdout) console.log(`[${logKey}]\tOutput:`, stdout);
                    if (stderr) console.error(`[${logKey}]\tError:`, stderr);
                    throw ex;
                }
            }
        }

        const roots = Array.isArray(project.roots)
            ? project.roots.map(root => path.join(dir, root))
            : [dir];

        const getRecord = (project, rec) => {
            const res = {
                project: project.name,
                repo: project.repo,
                tag: project.tag,
                hash: project.hash,
                timestamp: {
                    commit: project.timestamp,
                    scan: now
                },
                package: (rec.group ? rec.group + '/' : '') + rec.name,
                version: rec.version,
                purl: rec.purl,
                scope: rec.scope,
                ecosystem: rec.supplier,
            };
            const licenses = rec.licenses?.map?.(lic => lic.license?.id)
                .filter(lic => lic);

            if (licenses?.length) res.licenses = licenses;

            return res;
        };

        const records = [];
        const purls = [];
        for (let root of roots) {
            let rel = path.relative(dir, root);
            if (rel) rel = ` in ${rel}`;
            console.log(`[${logKey}]\tGenerating BOM${rel}...`);
            // Generate SBOM
            const bomNSData = await bom.createBom(root, {
                dev: true,
                multiProject: true,
                depth: 100,
                installDeps: true,
            });
            console.log(`[${logKey}]\t${bomNSData.bomJson.components.length} components identified${rel}`);

            // Transform SBOM to the storage structure
            let hasJava = false
            bomNSData.bomJson.components.forEach(rec => {
                if (rec.purl) {
                    if (purls.includes(rec.purl)) return;
                    if (rec.purl?.startsWith?.('pkg:maven/')) hasJava = true;
                    purls.push(rec.purl);
                }
                records.push(getRecord(project, rec));
            });

            if (hasJava) {
                const bomJData = await bom.createBom(dir, {
                    dev: true,
                    multiProject: false,
                    projectType: 'java',
                    depth: 100,
                    installDeps: true,
                    gradleMultiMode: true
                });

                if (bomJData) {
                    console.log(`[${logKey}]\t${bomJData.bomJson.components.length} additional components identified${rel}`);

                    bomJData.bomJson.components.forEach(rec => {
                        if (rec.purl) {
                            if (purls.includes(rec.purl)) return;
                            if (rec.purl?.startsWith?.('pkg:maven/')) hasJava = true;
                            purls.push(rec.purl);
                        }
                        records.push(getRecord(project, rec));
                    });
                }
            }
        }

        // Clean cache
        await fs.remove(dir);

        if (records.length === 0) {
            console.error(`[${logKey}]\tFailed to generate SBOM; bailing out.`);
            return;
        }

        // Save records
        console.log(`[${logKey}]\tIndexing...`);
        await OpenSearch.indexDocs(indexName, records);
        if (!(await OpenSearch.containsProject('sbom-all', project))) {
            await OpenSearch.indexDocs('sbom-all', records);
        }
        console.log(`[${logKey}]\tCompleted indexing`);
    }

    // Make sure aliases match
    await OpenSearch.pointAlias(normalizer.getAliasName(project), indexName);
};

parentPort.on('message', async project => {
    await run(project);
    parentPort.postMessage('done');
});

module.exports = {
    run
}