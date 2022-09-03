const OpenSearch = require("../opensearch");
const normalizer = require("../normalizer");
const semver = require("semver");
const config = require("../config");
const { awaitAll } = require("../awaitAll");
const constants = require('./constants')

const indices = config.get('opensearch.indices');

const scanTimestamp = Date.now();

function* chunks(arr, n) {
    for (let i = 0; i < arr.length; i += n) {
        yield arr.slice(i, i + n);
    }
}

const checkProject = async (name, tag, hash, excluded) => {
    const [{ _source: { project, packages, timestamp } }] = await OpenSearch.search(indices.sboms, {
        query: {
            bool: {
                filter: [
                    { term: { 'project.name': { value: name } } },
                    { term: { 'project.hash': { value: hash } } },
                    { term: { 'project.tag': { value: tag } } }
                ]
            }
        },
        _source: ['project', 'packages', 'timestamp.commit']
    }, 1);

    console.log(`Found ${packages.length} dependencies`);

    const packageMap = {};
    const reported = new Set();
    packages.forEach(package => {
        if (!packageMap[package.name]) packageMap[package.name] = [];
        packageMap[package.name].push(package);
    });

    const vulnerabilities = [];
    const count = {
        severe: 0,
        minor: 0
    };

    const excludedAdvisories = [
        ...(excluded.advisories.get(`${name}/${tag}`) || []),   // by tag
        ...(excluded.advisories.get(`${name}/*`) || []),        // by project
    ];

    const packageMapKeys = Object.keys(packageMap);
    for await (const packages of chunks(packageMapKeys, 300)) {
        const advisories = await OpenSearch.search(indices.advisories, {
            query: {
                bool: {
                    filter: [
                        {
                            nested: {
                                path: 'products',
                                query: {
                                    bool: {
                                        should: packages.map(package => [
                                            { term: { "products.name": package } },
                                            { wildcard: { "products.name": { value: `*\\/${package}` } } }
                                        ]).flat()
                                    }
                                }
                            }
                        },
                        { bool: { must_not: [{ term: { withdrawn: true } }] } }
                    ]
                }
            },
            _source: ['id', 'aliases', 'products', 'title', 'severity', 'ecosystem']
        }, 1000, null, true);

        for (const { _source: { id, aliases, products, title, severity, ecosystem: ecosystem_ } } of advisories) {
            const ecosystems = ecosystem_
                ? Array.isArray(ecosystem_)
                    ? ecosystem_.length
                        ? ecosystem_
                        : undefined
                    : [ecosystem_]
                : undefined;
            const vulnerabilitiesExcludedAtRule = new Map();
            const markedPackages = new Set();

            for (const product of products) {
                if (!Array.isArray(packageMap[product.name])) continue;

                for (const package of packageMap[product.name]) {
                    const coercedVersion = semver.coerce(package.version, { loose: true })?.version;
                    const satisfies = semver.satisfies(coercedVersion, product.version, { loose: true });
                    if (!satisfies) continue;

                    if (ecosystems && !ecosystems.includes(package.ecosystem)) continue;

                    const dupeKey = `${id}#${package.name}#${package.version}#${project}#${tag}#${hash}`;
                    if (reported.has(dupeKey)) continue;

                    const res = {
                        id,
                        aliases,
                        title,
                        severity: normalizer.normalize.severity(severity),
                        package: {
                            name: package.name,
                            version: package.version,
                            purl: package.purl,
                        },
                    };
                    if (package.ecosystem) res.package.ecosystem = package.ecosystem;
                    if (package.origin) res.package.origin = package.origin;

                    let aliasesExcludedByRule = excluded.rules.get(`${product.ecosystem || '*'}/${product.name}/${product.version}`);
                    if (!aliasesExcludedByRule && product.ecosystem) aliasesExcludedByRule = excluded.rules.get(`*/${product.name}/${product.version}`);
                    if (aliasesExcludedByRule?.some?.(alias => aliases.includes(alias))) {
                        res.excluded = 'AT_RULE';
                        vulnerabilitiesExcludedAtRule.set(package.purl, res);
                        continue;
                    }

                    if (aliases.some(alias => excludedAdvisories.includes(alias))) {
                        res.excluded = 'AT_PROJECT';
                    }

                    vulnerabilities.push(res);
                    markedPackages.add(package.purl);

                    if (!res.excluded) count[constants.HIGH_SEVS.includes(res.severity) ? 'severe' : 'minor']++;

                    reported.add(dupeKey);
                }
            }

            // if a package was excluded by rule but not by alias, add it back
            for (const [purl, res] of vulnerabilitiesExcludedAtRule) {
                if (!markedPackages.has(purl)) vulnerabilities.push(res);
            }
        }
    }

    console.log(`Found ${vulnerabilities.length} vulnerabilities`);

    await OpenSearch.indexDoc(indices.scans, {
        project,
        vulnerabilities,
        count,
        timestamp: {
            scan: scanTimestamp,
            commit: timestamp.commit
        }
    });
};

const getExcludedAdvisoriesMap = async () => {
    const [
        excludedAdvisories,
        excludedRules
    ] = await awaitAll([
        OpenSearch.search(indices['excluded-advisories'], {
            _source: ['aliases', 'project', 'tag']
        }, 1000, null, true),
        OpenSearch.search(indices['excluded-rules'], {
            _source: ['aliases', 'ecosystem', 'package', 'rule']
        }, 1000, null, true),
    ]);

    const excludedAdvisoriesMap = new Map();
    excludedAdvisories.forEach(({_source: {aliases, project, tag}}) => {
        const key = `${project}/${tag || '*'}`;
        if (excludedAdvisoriesMap.has(key)) excludedAdvisoriesMap.get(key).push(...aliases);
        else excludedAdvisoriesMap.set(key, aliases);
    });

    const excludedRulesMap = new Map();
    excludedRules.forEach(({_source: {aliases, ecosystem, package, rule}}) => {
        const key = `${ecosystem || '*'}/${package}/${rule}`;
        if (excludedRulesMap.has(key)) excludedRulesMap.get(key).push(...aliases);
        else excludedRulesMap.set(key, aliases);
    });

    return {
        advisories: excludedAdvisoriesMap,
        rules: excludedRulesMap
    };
};

const run = async ({project, tag, hash} = {}) => {
    const params = {};
    if (project || tag || hash) {
        params.query = {
            bool: {
                filter: []
            }
        };

        if (project) {
            params.query.bool.filter.push({ term: { 'project.name': { value: project } } });
            if (tag) {
                params.query.bool.filter.push({ term: { 'project.tag': { value: tag } } });
                if (hash) {
                    params.query.bool.filter.push({ term: { 'project.hash': { value: hash } } });
                }
            }
        }
    }

    const [
        projectAggs,
        exclusionMap
    ] = await awaitAll([
        OpenSearch.getAggregates(indices.sbom, {
            aggs: {
                projects: {
                    terms: { field: "project.name", order: { _key: 'asc' }, size: 10000 },
                    aggs: {
                        tags: {
                            terms: { field: "project.tag", order: { _key: 'asc' }, size: 10000 },
                            aggs: {
                                commit: {
                                    top_hits: {
                                        sort: [{ 'timestamp.commit': { order: 'desc' }}],
                                        _source: {
                                            includes: ['project', 'timestamp']
                                        },
                                        size: 1
                                    }
                                }
                            }
                        }
                    }
                }
            },
            ...params,
        }),
        getExcludedAdvisoriesMap()
    ]);

    const projects = [];
    for (const { tags: { buckets } } of projectAggs.projects.buckets) {
        for (const { commit: { hits: { hits } } } of buckets) {
            for (const { _source: { project: { name, tag, hash } } } of hits) {
                projects.push({ name, tag, hash });
            }
        }
    }

    let cnt = 0;
    let size = projects.length;
    for (const { name, tag, hash } of projects) {
        console.log(`Checking ${++cnt}/${size} ${name}@${tag} #${hash}...`);

        await checkProject(name, tag, hash, exclusionMap);
    }
};

module.exports = {
    run
}