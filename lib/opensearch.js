const config = require('./config');
const { Client } = require('@opensearch-project/opensearch');
const { awaitAll } = require("./awaitAll");
const { sleep } = require("./sleep");

const client = new Client({
    node: config.get('opensearch.domain.endpoint'),
    auth: config.get('opensearch.auth'),
    compression: 'gzip',
});

const indices = config.get('opensearch.indices');
const BULK_LIMIT = config.get('opensearch.limits.bulk') || 10000;
const QUERY_CLAUSE_LIMIT = config.get('opensearch.limits.clauses') || 200;

const initIndices = async () => {
    const SCANS_TEMPLATE = `${indices.scans}-template`;
    const SBOMS_TEMPLATE = `${indices.sboms}-template`;
    const ADVISORIES_TEMPLATE = `${indices.advisories}-template`;
    const NOTES_TEMPLATE = `${indices.notes}-template`;
    const PROGRESS_TEMPLATE = `${indices.progress}-template`;
    const EXCLUDED_ADVISORIES_TEMPLATE = `${indices['excluded-advisories']}-template`;
    const EXCLUDED_RULES_TEMPLATE = `${indices['excluded-rules']}-template`;

    const [
        { body: scansTemplateExists },
        { body: sbomsTemplateExists },
        { body: advisoriesTemplateExists },
        { body: notesTemplateExists },
        { body: progressTemplateExists },
        { body: excludedAdvisoriesTemplateExists },
        { body: excludedRulesTemplateExists },
    ] = await awaitAll([
        client.indices.existsIndexTemplate({ name: SCANS_TEMPLATE }),
        client.indices.existsIndexTemplate({ name: SBOMS_TEMPLATE }),
        client.indices.existsIndexTemplate({ name: ADVISORIES_TEMPLATE }),
        client.indices.existsIndexTemplate({ name: NOTES_TEMPLATE }),
        client.indices.existsIndexTemplate({ name: PROGRESS_TEMPLATE }),
        client.indices.existsIndexTemplate({ name: EXCLUDED_ADVISORIES_TEMPLATE }),
        client.indices.existsIndexTemplate({ name: EXCLUDED_RULES_TEMPLATE }),
    ]);

    // scans-all
    if (!scansTemplateExists) {
        console.log('Creating template for Scans');
        await client.indices.putIndexTemplate({
            name: SCANS_TEMPLATE,
            body: {
                index_patterns: [`${indices.scans}-*`],
                template: {
                    settings: {
                        'plugins.index_state_management.rollover_alias': indices.scans,
                        number_of_replicas: "2",
                        number_of_shards: "5",
                        max_inner_result_window: "1000"
                    },
                    mappings: {
                        properties: {
                            count: {
                                properties: {
                                    severe: {
                                        type: "short"
                                    },
                                    minor: {
                                        type: "short"
                                    }
                                }
                            },
                            project: {
                                properties: {
                                    name: {
                                        type: "keyword",
                                        fields: { text: { type: "text" } }
                                    },
                                    repo: {
                                        type: "keyword",
                                        fields: { text: { type: "text" } }
                                    },
                                    tag: {
                                        type: "keyword",
                                        fields: { text: { type: "text" } }
                                    },
                                    hash: {
                                        type: "keyword",
                                        fields: { text: { type: "text" } }
                                    },
                                }
                            },
                            vulnerabilities: {
                                type: "nested",
                                properties: {
                                    id: {
                                        type: "keyword",
                                        fields: { text: { type: "text" } }
                                    },
                                    aliases: {
                                        type: "keyword",
                                        fields: { text: { type: "text" } }
                                    },
                                    title: {
                                        type: "keyword",
                                        fields: { text: { type: "text" } }
                                    },
                                    severity: {
                                        type: "keyword"
                                    },
                                    package: {
                                        type: "nested",
                                        properties: {
                                            name: {
                                                type: "keyword",
                                                fields: {
                                                    text: {
                                                        type: "text",
                                                    }
                                                }
                                            },
                                            version: {
                                                type: "keyword",
                                                fields: {
                                                    text: {
                                                        type: "text",
                                                    }
                                                }
                                            },
                                            ecosystem: {
                                                type: "keyword",
                                                fields: {
                                                    text: {
                                                        type: "text",
                                                    }
                                                }
                                            },
                                            origin: {
                                                type: "keyword",
                                                fields: {
                                                    text: {
                                                        type: "text",
                                                    }
                                                }
                                            },
                                            purl: {
                                                type: "keyword",
                                                fields: {
                                                    text: {
                                                        type: "text",
                                                    }
                                                }
                                            },
                                        },
                                    },
                                    excluded: {
                                        type: "keyword"
                                    },
                                }
                            },
                            examined: { type: "boolean" },
                            timestamp: {
                                properties: {
                                    commit: {
                                        type: "date"
                                    },
                                    scan: {
                                        type: "date"
                                    }
                                }
                            },
                        }
                    }
                }
            }
        });
    }

    try {
        await client.transport.request({
            method: 'GET',
            path: `/_plugins/_ism/policies/${indices.scans}-rollover-policy`,
            body: {},
            querystring: {}
        });
    } catch {
        console.log('Creating rollover policy for Scans');
        await client.transport.request({
            method: 'PUT',
            path: `/_plugins/_ism/policies/${indices.scans}-rollover-policy`,
            body: {
                policy: {
                    description: `${indices.scans}-rollover-policy`,
                    default_state: "rollover",
                    states: [
                        {
                            name: "rollover",
                            actions: [{ rollover: { min_doc_count: 100000 } }],
                            transitions: []
                        }
                    ],
                    ism_template: {
                        index_patterns: [`${indices.scans}-*`],
                        priority: 100
                    }
                }
            },
            querystring: {}
        });
    }

    if (!(await aliasExists(indices.scans))) {
        console.log('Creating alias for Scans');
        await client.indices.create({
            index: `${indices.scans}-000001`,
            body: {
                aliases: {
                    [indices.scans]: {
                        is_write_index: true
                    }
                }
            }
        });
    }
    // End of scans-all

    // sboms
    if (!sbomsTemplateExists) {
        console.log('Creating template for SBOMs');
        await client.indices.putIndexTemplate({
            name: SBOMS_TEMPLATE,
            body: {
                index_patterns: [`${indices.sboms}-*`],
                template: {
                    settings: {
                        'plugins.index_state_management.rollover_alias': indices.sboms,
                        number_of_replicas: "2",
                        number_of_shards: "5"
                    },
                    mappings: {
                        properties: {
                            project: {
                                properties: {
                                    name: {
                                        type: "keyword",
                                        fields: { text: { type: "text" } }
                                    },
                                    repo: {
                                        type: "keyword",
                                        fields: { text: { type: "text" } }
                                    },
                                    tag: {
                                        type: "keyword",
                                        fields: { text: { type: "text" } }
                                    },
                                    hash: {
                                        type: "keyword",
                                        fields: { text: { type: "text" } }
                                    },
                                }
                            },
                            packages: {
                                type: "nested",
                                properties: {
                                    name: {
                                        type: "keyword",
                                        fields: { text: { type: "text" } }
                                    },
                                    version: {
                                        type: "keyword",
                                        fields: { text: { type: "text" } }
                                    },
                                    purl: {
                                        type: "keyword",
                                        fields: { text: { type: "text" } }
                                    },
                                    licenses: {
                                        type: "keyword",
                                    },
                                    scope: {
                                        type: "keyword",
                                    },
                                    ecosystem: {
                                        type: "keyword",
                                        fields: { text: { type: "text" } }
                                    },
                                    origin: {
                                        type: "keyword",
                                        fields: { text: { type: "text" } }
                                    },
                                }
                            },
                            timestamp: {
                                properties: {
                                    commit: {
                                        type: "date"
                                    },
                                    scan: {
                                        type: "date"
                                    }
                                }
                            },
                        }
                    }
                }
            }
        });
    }

    try {
        await client.transport.request({
            method: 'GET',
            path: `/_plugins/_ism/policies/${indices.sboms}-rollover-policy`,
            body: {},
            querystring: {}
        });
    } catch {
        console.log('Creating rollover policy for SBOMs');
        await client.transport.request({
            method: 'PUT',
            path: `/_plugins/_ism/policies/${indices.sboms}-rollover-policy`,
            body: {
                policy: {
                    description: `${indices.sboms}-rollover-policy`,
                    default_state: "rollover",
                    states: [
                        {
                            name: "rollover",
                            actions: [{ rollover: { min_doc_count: 100000 } }],
                            transitions: []
                        }
                    ],
                    ism_template: {
                        index_patterns: [`${indices.sboms}-*`],
                        priority: 100
                    }
                }
            },
            querystring: {}
        });
    }

    if (!(await aliasExists(indices.sboms))) {
        console.log('Creating alias for SBOMs');
        await client.indices.create({
            index: `${indices.sboms}-000001`,
            body: {
                aliases: {
                    [indices.sboms]: {
                        is_write_index: true
                    }
                }
            }
        });
    }
    // End of sboms-all

    // advisories
    if (!advisoriesTemplateExists) {
        console.log('Creating template for Advisories');
        await client.indices.putIndexTemplate({
            name: ADVISORIES_TEMPLATE,
            body: {
                index_patterns: [`${indices.advisories}-*`],
                template: {
                    mappings: {
                        properties: {
                            id: {
                                type: "keyword",
                                fields: { text: { type: "text" } }
                            },
                            aliases: {
                                type: "keyword",
                                fields: { text: { type: "text" } }
                            },
                            title: {
                                type: "text"
                            },
                            description: {
                                type: "text"
                            },
                            severity: {
                                type: "keyword"
                            },
                            products: {
                                type: "nested",
                                properties: {
                                    vendor: {
                                        type: "keyword",
                                        fields: { text: { type: "text" } }
                                    },
                                    package: {
                                        type: "keyword",
                                        fields: { text: { type: "text" } }
                                    },
                                    name: {
                                        type: "keyword",
                                        fields: { text: { type: "text" } }
                                    },
                                    version: {
                                        type: "keyword",
                                        fields: { text: { type: "text" } }
                                    },
                                    ecosystem: {
                                        type: "keyword",
                                        fields: { text: { type: "text" } }
                                    },
                                    source: {
                                        type: "keyword",
                                        fields: { text: { type: "text" } }
                                    },
                                }
                            },
                            ecosystem: {
                                type: "keyword",
                                fields: {
                                    text: {
                                        type: "text",
                                    }
                                }
                            },
                            timestamp: {
                                properties: {
                                    publish: {
                                        type: "date"
                                    },
                                    scan: {
                                        type: "date"
                                    }
                                }
                            },
                            withdrawn: {
                                type: "boolean"
                            }
                        }
                    }
                }
            }
        });
    }
    // End of advisories

    // notes
    if (!notesTemplateExists) {
        console.log('Creating template for Notes');
        await client.indices.putIndexTemplate({
            name: NOTES_TEMPLATE,
            body: {
                index_patterns: [indices.notes],
                template: {
                    settings: {
                        number_of_shards: "2"
                    },
                    mappings: {
                        properties: {
                            user: {
                                type: "keyword",
                                fields: {
                                    text: {
                                        type: "text",
                                    }
                                }
                            },
                            aliases: {
                                type: "keyword",
                                fields: {
                                    text: {
                                        type: "text",
                                    }
                                }
                            },
                            note: {
                                type: "text"
                            },
                            timestamp: {
                                type: "date"
                            },
                        }
                    }
                }
            }
        });
    }

    if (!(await indexExists(indices.notes))) {
        console.log('Creating index for Notes');
        await client.indices.create({
            index: indices.notes,
        });
    }
    // End of notes

    // progress
    if (!progressTemplateExists) {
        console.log('Creating template for Progress');
        await client.indices.putIndexTemplate({
            name: PROGRESS_TEMPLATE,
            body: {
                index_patterns: [indices.progress],
                template: {
                    settings: {
                        number_of_shards: "2"
                    },
                    mappings: {
                        properties: {
                            project: {
                                properties: {
                                    name: {
                                        type: "keyword",
                                        fields: { text: { type: "text" } }
                                    },
                                    repo: {
                                        type: "keyword",
                                        fields: { text: { type: "text" } }
                                    },
                                    tag: {
                                        type: "keyword",
                                        fields: { text: { type: "text" } }
                                    },
                                    hash: {
                                        type: "keyword",
                                        fields: { text: { type: "text" } }
                                    },
                                }
                            },
                            type: {
                                type: "keyword"
                            },
                            state: {
                                type: "keyword"
                            },
                            timestamp: {
                                properties: {
                                    created: { type: "date" },
                                    updated: { type: "date" },
                                }
                            },
                        }
                    }
                }
            }
        });
    }

    if (!(await indexExists(indices.progress))) {
        console.log('Creating index for Progress');
        await client.indices.create({
            index: indices.progress,
        });
    }
    // End of progress

    // excluded-advisories
    if (!excludedAdvisoriesTemplateExists) {
        console.log('Creating template for Excluded Advisories');
        await client.indices.putIndexTemplate({
            name: EXCLUDED_ADVISORIES_TEMPLATE,
            body: {
                index_patterns: [indices['excluded-advisories']],
                template: {
                    settings: {
                        number_of_shards: "2"
                    },
                    mappings: {
                        properties: {
                            aliases: {
                                type: "keyword",
                                fields: {
                                    text: {
                                        type: "text",
                                    }
                                }
                            },
                            project: {
                                type: "keyword",
                                fields: {
                                    text: {
                                        type: "text",
                                    }
                                }
                            },
                            tag: {
                                type: "keyword",
                                fields: {
                                    text: {
                                        type: "text",
                                    }
                                }
                            },
                            user: {
                                type: "keyword",
                                fields: {
                                    text: {
                                        type: "text",
                                    }
                                }
                            },
                            timestamp: {
                                type: "date"
                            },
                        }
                    }
                }
            }
        });
    }

    if (!(await indexExists(indices['excluded-advisories']))) {
        console.log('Creating index for Excluded Advisories');
        await client.indices.create({
            index: indices['excluded-advisories'],
        });
    }
    // End of excluded-advisories

    // ignored-rules
    if (!excludedRulesTemplateExists) {
        console.log('Creating template for Ignored Rules');
        await client.indices.putIndexTemplate({
            name: EXCLUDED_RULES_TEMPLATE,
            body: {
                index_patterns: [indices['excluded-rules']],
                template: {
                    settings: {
                        number_of_shards: "2"
                    },
                    mappings: {
                        properties: {
                            aliases: {
                                type: "keyword",
                                fields: {
                                    text: {
                                        type: "text",
                                    }
                                }
                            },
                            ecosystem: {
                                type: "keyword",
                                fields: {
                                    text: {
                                        type: "text",
                                    }
                                }
                            },
                            package: {
                                type: "keyword",
                                fields: {
                                    text: {
                                        type: "text",
                                    }
                                }
                            },
                            rule: {
                                type: "keyword",
                                fields: {
                                    text: {
                                        type: "text",
                                    }
                                }
                            },
                            user: {
                                type: "keyword",
                                fields: {
                                    text: {
                                        type: "text",
                                    }
                                }
                            },
                            timestamp: {
                                type: "date"
                            },
                        }
                    }
                }
            }
        });
    }

    if (!(await indexExists(indices['excluded-rules']))) {
        console.log('Creating index for Ignored Rules');
        await client.indices.create({
            index: indices['excluded-rules'],
        });
    }
};

const deleteDocs = async (index, terms) => {
    if (!index?.trim()) throw 'Invalid index name';
    if (!terms) throw 'Invalid terms object';

    const result = await client.deleteByQuery({
        index,
        body: {
            query: {
                bool: {
                    must: Object.keys(terms).map(key => ({ term: { [key]: { value: terms[key] } } }))
                }
            }
        },
        slices: 'auto',
        refresh: true
    });

    console.log(`Deleted ${result.body.deleted}/${result.body.total}`);
};

const markScansAsExamined = async (filters, attempt = 0) => {
    if (!Array.isArray(filters)) {
        console.warn(`markScansAsExamined with invalid filters: ${typeof filters}`);
        return;
    }

    const len = filters.length;
    console.log(`markScansAsExamined with ${len} filters`);
    if (len === 0) return;

    // Used to de-dupe error types
    const errors = new Set();

    for (let i = 0; i < len; i += QUERY_CLAUSE_LIMIT) {
        const result = await client.updateByQuery({
            index: indices.scans,
            body: {
                query: {
                    bool: {
                        must: [
                            {
                                bool: {
                                    should: [
                                        { match: { examined: false } },
                                        { bool: { must_not: { exists: { field: 'examined' } } } }
                                    ]
                                }
                            },
                            { bool: { should: filters.slice(i, i + QUERY_CLAUSE_LIMIT) } }
                        ]
                    }
                },
                script: {
                    lang: 'painless',
                    source: 'ctx._source["examined"] = true'
                }
            },
            conflicts: 'proceed',
            wait_for_completion: true,
            refresh: true
        });

        const success = result?.statusCode === 200;
        if (!success) {
            console.log(result.meta?.body?.error);
            console.warn('markScansAsExamined failed');
            // Just logging; no harm can come
        }

        if (result.body.errors) {
            result.body.items.forEach(error => {
                if (error.index?.error?.type && !errors.has(error.index.error.type)) {
                    console.warn('markScansAsExamined Error:', error.index.error);
                    errors.add(error.index.error.type);
                }
            });
        }
    }
};

const indexDocs = async (index, docs) => {
    if (!index?.trim()) throw 'Invalid index name';
    if (!Array.isArray(docs)) throw 'Invalid docs array';

    const len = docs.length;
    if (len === 0) {
        const exists = await indexExists(index);
        if (!exists) await client.indices.create({ index });
        return;
    }

    const errors = new Set();

    for (let i = 0; i < len; i += BULK_LIMIT) {
        const body = docs
            .slice(i, i + BULK_LIMIT)
            .flatMap(doc => ([
                { index: { _index: index } },
                doc
            ]));

        const result = await client.bulk({ refresh: true, body });

        const success = result?.statusCode === 200;
        if (!success) {
            console.log(result.meta?.body?.error);
            console.log(result);
            throw 'Bulk index failed';
        }

        if (result.body.errors) {
            result.body.items.forEach(error => {
                if (error.index?.error?.type && !errors.has(error.index.error.type)) {
                    console.log(error.index.error);
                    errors.add(error.index.error.type);
                }
            });
            throw 'Bulk index failed';
        }
    }
};

const indexDoc = async (index, doc) => {
    if (!index?.trim()) throw 'Invalid index name';

    const exists = await indexExists(index);
    if (!exists) await client.indices.create({ index });

    const result = await client.index({
        index,
        body: doc,
        refresh: true,
    });

    const success = result?.statusCode === 201;
    if (!success) {
        console.log(result.meta?.body?.error);
        console.log(result);
        throw 'Index failed';
    }

    return result.body?._id;
};

const indexExists = async index => {
    const { body } = await client.indices.exists({ index });
    return body;
};

const aliasExists = async name => {
    const { body } = await client.indices.existsAlias({ name, ignore_unavailable: true });
    return body;
};

const pointAlias = async (name, index, deleteOldIndex) => {
    console.log(`Checking if alias ${name} exists...`);
    const aliasExists_ = await aliasExists(name);
    const indexExists_ = await indexExists(index);

    if (!indexExists_) await client.indices.create({ index });

    let aliasExistsAndIsPointingToIndex = false;
    if (aliasExists_) {
        console.log(`Getting alias ${name} ...`);
        const { body: resGetAlias } = await client.indices.getAlias({ name, ignore_unavailable: true });
        const indices = Object.keys(resGetAlias);
        for await (let aliasIndex of indices) {
            if (aliasIndex === index) {
                aliasExistsAndIsPointingToIndex = true;
            } else {
                console.log(`Deleting alias ${name} ...`);
                await client.indices.deleteAlias({ name, index: aliasIndex });

                if (deleteOldIndex) {
                    do {
                        console.log(`Deleting old index ${aliasIndex} ... `);
                        try {
                            await client.indices.delete({ index: aliasIndex });
                            break;
                        } catch (ex) {
                            if (/snapshot/i.test(ex.message)) {
                                await sleep(15000);
                            }
                        }
                    } while (true);
                }
            }
        }
    } else {
        console.log(`No alias found named ${name}`);
    }

    if (aliasExistsAndIsPointingToIndex) {
        console.log(`All good with alias ${name}`);
    } else {
        console.log(`Creating alias ${name} ...`);
        await client.indices.putAlias({ name, index });
        console.log(`Created alias ${name}`);
    }
};

// ToDo: increase composite size
const getUniques = async (index, fields, after) => {
    const _fields = Array.isArray(fields) ? fields : [fields];
    const key = 'uniques';
    let { body } = await client.search({
        index,
        body: {
            aggs: {
                [key]: {
                    composite: {
                        sources: _fields.map(field => ({
                            [field]: {
                                terms: {
                                    field
                                }
                            }
                        })),
                        after
                    }
                }
            }
        },
        size: 0
    });

    const data = [];
    const _addAggs = buckets => {
        data.push(...buckets.map(bucket => bucket.key));
    }

    _addAggs(body.aggregations[key].buckets);

    if (body.aggregations[key].after_key)
        data.push(...(await getUniques(index, fields, body.aggregations[key].after_key)));

    return data;
};

const getAggregates = async (index, body, after) => {
    const req = {
        index,
        body,
        size: 0
    };

    let attempt = 0;


    do {
        try {
            let { body: res } = await client.search(req);
            return res.aggregations;
        } catch (ex) {
            console.log(`Failed in getAggregates (${attempt})`, ex);
            if (ex.meta?.statusCode === 429) await sleep(3000);
            if (attempt > 2) throw ex;

            await sleep(1000 * attempt + 500);
        }
        attempt++;
    } while (true);
};

const _search = async (index, body, size = 100, transform = null, loop = false, attempt = 0) => {
    let res;

    try {
        res = await client.search({
            index,
            body,
            scroll: loop ? '10s' : undefined,
            size
        });
    } catch (ex) {
        console.log(`Failed in search (${attempt})`, ex);
        if (ex.meta?.statusCode === 429) await sleep(3000);
        if (attempt > 2) throw ex;

        await sleep(1000 * attempt + 500);
        return await _search(index, body, size, transform, loop, attempt + 1);
    }
    const data = [];
    const _addHits = hits => {
        if (transform) {
            data.push(...hits.map(transform));
        } else {
            data.push(...hits);
        }
    }
    _addHits(res.body.hits.hits);
    if (!loop || !res.body._scroll_id || res.body.hits.hits.length === 0) return data;

    let scrollId = res.body._scroll_id;
    const scrollIds = [scrollId];
    do {
        res = await scroll(scrollId);
        if (res.body.hits.hits.length === 0) break;
        scrollId = res.body._scroll_id;
        scrollIds.push(scrollId);
        _addHits(res.body.hits.hits);
    } while (scrollId);

    try {
        await client.clearScroll({ body: { scroll_id: scrollIds } });
    } catch (ex) {
        // Do nothing
    }

    return data;
};

const search = async (index, body, size = 100, transform = null, loop = false) => {
    return await _search(index, body, size, transform, loop);
}

const scroll = async scrollId => {
    let attempt = 0;
    do {
        try {
            return client.scroll({
                body: {
                    scroll_id: scrollId,
                    scroll: '30s',
                }
            });
        } catch (ex) {
            console.log(`Failed in scroll (${attempt})`, ex);
            if (ex.meta?.statusCode === 429) await sleep(1000);
            if (attempt > 2) throw ex;

            // time sensitive so faster retries
            await sleep(500 * attempt + 100);
        }
        attempt++;
    } while (true);
}

const containsProject = async project => {
    if (!project || !project.name || !project.hash || !project.tag) return;

    const res = await client.count({
        index: indices.sboms,
        body: {
            query: {
                bool: {
                    filter: [
                        { term: { 'project.name': { value: project.name } } },
                        { term: { 'project.hash': { value: project.hash } } },
                        { term: { 'project.tag': { value: project.tag } } }
                    ]
                }
            }
        }
    });

    return res.body?.count > 0;
};

const lockProgressState = async (project, type, state = 'locked') => {
    if (!type || !project || !project.name || !project.hash || !project.tag) return;

    const lockedQuery = await client.count({
        index: indices.progress,
        body: {
            query: {
                bool: {
                    filter: [
                        { term: { 'project.name': { value: project.name } } },
                        { term: { 'project.hash': { value: project.hash } } },
                        { term: { 'project.tag': { value: project.tag } } },
                        { term: { type: { value: type } } },
                        { term: { state: { value: state } } },
                        { range: { 'timestamp.created': { gte: 'now-3h/h' } } }
                    ]
                }
            }
        }
    });

    if (lockedQuery.body?.count > 0) return false;

    return await indexDoc(indices.progress, {
        project: {
            name: project.name,
            repo: project.repo,
            tag: project.tag,
            hash: project.hash,
        },
        type,
        state,
        timestamp: {
            created: Date.now()
        }
    });
};

const _updateProgressState = async (id, type, state = 'done', attempt = 0) => {
    if (!type || !id) return;

    try {
        await client.update({
            index: indices.progress,
            id,
            refresh: true,
            body: {
                doc: {
                    state,
                    timestamp: {
                        updated: Date.now()
                    }
                }
            }
        });
    } catch (ex) {
        console.log(`Failed in updateProgressState (${attempt})`, ex);
        if (ex.meta?.statusCode === 429) await sleep(3000);
        if (attempt > 2) throw ex;

        await sleep(1000 * attempt + 500);
        await _updateProgressState(id, type, state, attempt + 1);
    }
};

const updateProgressState = async (id, type, state = 'done') => {
    await _updateProgressState(id, type, state);
}

const containsVulnerability = async (indexName, project, package, id) => {
    const res = await client.search({
        index: indexName,
        body: {
            query: {
                bool: {
                    must: [
                        { term: { project: { value: project.name } } },
                        { term: { hash: { value: project.hash } } },
                        { term: { tag: { value: project.tag } } }
                    ]
                }
            }
        },
        size: 0
    });

    return res.body?.hits?.total?.value > 0;
};

function* chunks(arr, n) {
    for (let i = 0; i < arr.length; i += n) {
        yield arr.slice(i, i + n);
    }
}

module.exports = {
    initIndices,
    indexExists,
    pointAlias,
    getUniques,
    getAggregates,
    search,
    indexDocs,
    containsProject,
    deleteDocs,
    indexDoc,
    lockProgressState,
    updateProgressState,
    markScansAsExamined,
};