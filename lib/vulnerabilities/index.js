const OpenSearch = require("../opensearch");
const normalizer = require("../normalizer");
const semver = require("semver");
const config = require("../config");
const { awaitAll } = require("../awaitAll");

const prefixes = config.get('opensearch.prefixes');

const timestamp = Date.now();

function* chunks(arr, n) {
    for (let i = 0; i < arr.length; i += n) {
        yield arr.slice(i, i + n);
    }
}

const checkProject = async (project, tag, hash, exclusions) => {
    const bomAliasName = normalizer.getAliasName({ name: project, tag });
    const indexName = normalizer.getIndexName({ name: project, tag, hash }, `raw-${prefixes.vulnerabilities}`, '-' + timestamp);
    const aliasName = normalizer.getAliasName({ name: project, tag }, prefixes.vulnerabilities);

    await OpenSearch.deleteDocs(`${prefixes.vulnerabilities}all`, {project, tag, hash});

    const vulnerabilities = [];
    const packageVersions = await OpenSearch.search(bomAliasName, {
        query: {
            bool: {
                must: [
                    { term: { project: { value: project } } },
                    { term: { hash: { value: hash } } },
                    { term: { tag: { value: tag } } }
                ]
            }
        },
        _source: ['package', 'version', 'ecosystem', 'timestamp.commit']
    }, 1000, null, true);

    console.log(`Found ${packageVersions.length} dependencies`);

    const packageMap = {};
    const reported = new Set();
    packageVersions.forEach(({ _source: dependency }) => {
        if (!packageMap[dependency.package]) packageMap[dependency.package] = [];
        packageMap[dependency.package].push(dependency);
    });

    const packageMapKeys = Object.keys(packageMap);
    for await (const packages of chunks(packageMapKeys, 300)) {
        const advisories = await OpenSearch.search('advisories', {
            query: {
                bool: {
                    must: [
                        {
                            bool: {
                                should: packages.map(package => [
                                    { term: { "products.name": package } },
                                    { wildcard: { "products.name": { value: `*\\/${package}` } } }
                                ]).flat()
                            }
                        },
                        {
                            bool: {
                                must_not: [{ term: { withdrawn: true } }]
                            }
                        }
                    ]
                }
            },
            _source: ['id', 'aliases', 'products', 'title', 'severity', 'ecosystem']
        }, 1000, null, true);

        for (const { _source: { id, aliases, products, title, severity, ecosystem } } of advisories) {
            let packageName, packageVersion, packageEcosystem;
            let timeCommit;
            if (products.some(product => {
                return packageMap[product.name]?.some?.(package => {
                    const coercedVersion = semver.coerce(package.version, { loose: true })?.version;
                    const satisfies = semver.satisfies(coercedVersion, product.version, { loose: true });

                    if (!satisfies) return false;

                    if (Array.isArray(ecosystem)) {
                        if (ecosystem.length && !ecosystem.includes(package.ecosystem)) return false;
                    } else if (ecosystem && ecosystem !== package.ecosystem) return false;

                    packageName = package.package;
                    packageVersion = package.version;
                    packageEcosystem = package.ecosystem;
                    timeCommit = package.timestamp.commit;

                    const dupeKey = `${id}#${packageName}#${packageVersion}#${project}#${tag}#${hash}`;
                    if (reported.has(dupeKey)) return;

                    reported.add(dupeKey);

                    return true;
                });
            })) {
                const res = {
                    id,
                    aliases,
                    package: {
                        name: packageName,
                        version: packageVersion,
                    },
                    title,
                    severity: normalizer.normalize.severity(severity),
                    project,
                    tag,
                    hash,
                    timestamp: {
                        scan: timestamp,
                        commit: timeCommit
                    }
                };
                if (packageEcosystem) res.package.ecosystem = packageEcosystem;
                if (aliases.some(alias => exclusions.includes(alias))) res.excluded = true;
                vulnerabilities.push(res);
            }
        }
    }

    await OpenSearch.indexDocs(indexName, vulnerabilities);
    await OpenSearch.indexDocs(`${prefixes.vulnerabilities}all`, vulnerabilities);
    await OpenSearch.pointAlias(aliasName, indexName, true);
};

const run = async () => {
    const [
        projectTags,
        exclusions
    ] = await awaitAll([
        OpenSearch.getUniques('sbom-*~*', ['project', 'tag', 'hash']),
        OpenSearch.search('exclusions', {}, 1000, null, true)
    ]);

    const excludedIds = new Map();
    exclusions.forEach(({_source: {aliases, project, tag}}) => {
        const key = `${project}/${tag || '*'}`;
        if (excludedIds.has(key)) excludedIds.get(key).push(...aliases);
        else excludedIds.set(key, aliases);
    });

    let cnt = 0;
    let size = projectTags.length;
    for await (const projectTag of projectTags) {
        console.log(`Checking ${++cnt}/${size} ${projectTag.project}@${projectTag.tag} #${projectTag.hash}...`);
        const excludedByTag = excludedIds.get(`${projectTag.project}/${projectTag.tag}`) || [];
        const excludedByProject = excludedIds.get(`${projectTag.project}/*`) || [];
        await checkProject(projectTag.project, projectTag.tag, projectTag.hash, [...excludedByTag, ...excludedByProject]);
    }
};

module.exports = {
    run
}