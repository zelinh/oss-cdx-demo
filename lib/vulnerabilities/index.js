const OpenSearch = require("../opensearch");
const normalizer = require("../normalizer");
const semver = require("semver");

const timestamp = Date.now();

function* chunks(arr, n) {
    for (let i = 0; i < arr.length; i += n) {
        yield arr.slice(i, i + n);
    }
}

const checkProject = async (name, tag, hash) => {
    console.log(`Checking ${name}@${tag} #${hash}...`);
    const bomAliasName = 'raw-sbom-*';//normalizer.getAliasName({ name, tag });
    const indexName = 'raw-vulnerabilities-000001';//normalizer.getIndexName({ name, tag, hash }, 'raw-vulnerabilities-', timestamp);
    //const aliasName = normalizer.getAliasName({ name, tag }, 'vulnerabilities-');
    const vulnerabilities = [];
    const packageVersions = await OpenSearch.search(bomAliasName, {
        "query": {
            "bool": {
                "must": [
                    {
                        "term": {
                            "project": {
                                "value": name
                            }
                        }
                    },
                    {
                        "term": {
                            "tag": {
                                "value": tag
                            }
                        }
                    },
                    {
                        "term": {
                            "hash": {
                                "value": hash
                            }
                        }
                    }
                ]
            }
        },
        _source: ['package', 'version', 'ecosystem', 'timestamp.commit']
        //_source: ['package', 'version', 'ecosystem']
    }, 1000, null, true);

    console.log(`Found ${packageVersions.length} dependencies`);

    const packageMap = {};
    packageVersions.forEach(({ _source: dependency }) => {
        if (!packageMap[dependency.package]) packageMap[dependency.package] = [];
        packageMap[dependency.package].push(dependency);
    });

    const packageMapKeys = Object.keys(packageMap);
    for await (const packages of chunks(packageMapKeys, 100)) {
        const advisories = await OpenSearch.search('advisories', {
            query: {
                bool: {
                    must: [
                        {
                            bool: {
                                should: packages.map(package => [
                                    {
                                        term: {
                                            "products.name": package
                                        }
                                    },
                                    {
                                        wildcard: {
                                            "products.name": {
                                                value: `*\\/${package}`
                                            }
                                        }
                                    }
                                ]).flat()
                            }
                        },
                        {
                            bool: {
                                must_not: [
                                    {
                                        term: {
                                            withdrawn: true
                                        }
                                    }
                                ]
                            }
                        }
                    ]
                }
            },
            _source: ['id', 'products', 'title', 'severity', 'ecosystem']
        }, 1000, null, true);
        for (const { _source: { id, products, title, severity, ecosystem } } of advisories) {
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

                    return true;
                });
            })) {
                const res = {
                    id,
                    package: {
                        name: packageName,
                        version: packageVersion,
                    },
                    title,
                    severity: normalizer.normalize.severity(severity),
                    project: {
                        name,
                        tag,
                        hash
                    },
                    timestamp: {
                        scan: timestamp,
                        commit: timeCommit
                    }
                };
                if (packageEcosystem) res.package.ecosystem = packageEcosystem;
                vulnerabilities.push(res);
            }
        }
    }

    await OpenSearch.indexDocs(indexName, vulnerabilities);

    //await OpenSearch.pointAlias(aliasName, indexName);
};

const run = async () => {
    const projectTags = await OpenSearch.getUniques('raw-sbom-*', ['project', 'tag', 'hash']);
    for await (const projectTag of projectTags) {
        await checkProject(projectTag.project, projectTag.tag, projectTag.hash);
    }
};

module.exports = {
    run
}