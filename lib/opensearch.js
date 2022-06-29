const config = require('./config');
const { Client } = require('@opensearch-project/opensearch');
const { normalize } = require("./normalizer");
const { awaitAll } = require("./awaitAll");

const client = new Client({
    node: config.get('opensearch.domain.endpoint'),
    auth: config.get('opensearch.auth'),
    compression: 'gzip',
});

const prefixes = config.get('opensearch.prefixes');
const BULK_LIMIT = config.get('opensearch.limits.bulk') || 10000;

const initIndices = async () => {
    const CDX_COMPONENT_TEMPLATE = `${prefixes.sbom}component-template`;
    const CDX_TEMPLATE = `${prefixes.sbom}template`;
    const CDX_ALL_TEMPLATE = `${prefixes.sbom}all-template`;
    const ADVISORIES_TEMPLATE = `${prefixes.advisories}template`;
    const VULNERABILITIES_COMPONENT_TEMPLATE = `${prefixes.vulnerabilities}component-template`;
    const VULNERABILITIES_TEMPLATE = `${prefixes.vulnerabilities}template`;
    const VULNERABILITIES_ALL_TEMPLATE = `${prefixes.vulnerabilities}all-template`;
    const NOTES_TEMPLATE = `notes-template`;
    const EXCLUSIONS_TEMPLATE = `exclusions-template`;

    const [
        { body: cdxComponentTemplateExists },
        { body: cdxTemplateExists },
        { body: advisoriesTemplateExists },
        { body: vulnerabilitiesComponentTemplateExists },
        { body: vulnerabilitiesTemplateExists },
        { body: notesTemplateExists },
        { body: exclusionsTemplateExists },
    ] = await awaitAll([
        client.cluster.existsComponentTemplate({ name: CDX_COMPONENT_TEMPLATE }),
        client.indices.existsIndexTemplate({ name: CDX_TEMPLATE }),
        client.indices.existsTemplate({ name: ADVISORIES_TEMPLATE }),
        client.cluster.existsComponentTemplate({ name: VULNERABILITIES_COMPONENT_TEMPLATE }),
        client.indices.existsIndexTemplate({ name: VULNERABILITIES_TEMPLATE }),
        client.indices.existsTemplate({ name: NOTES_TEMPLATE }),
        client.indices.existsTemplate({ name: EXCLUSIONS_TEMPLATE }),
    ]);

    const putTemplateCalls = [];
    if (!cdxComponentTemplateExists) {
        console.log('Creating components for sbom');
        await client.cluster.putComponentTemplate({
            name: CDX_COMPONENT_TEMPLATE,
            body: {
                template: {
                    mappings: {
                        properties: {
                            project: {
                                type: "keyword",
                                fields: {
                                    text: {
                                        type: "text",
                                    }
                                }
                            },
                            repo: {
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
                            hash: {
                                type: "keyword",
                                fields: {
                                    text: {
                                        type: "text",
                                    }
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
                            package: {
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
                            purl: {
                                type: "keyword",
                                fields: {
                                    text: {
                                        type: "text",
                                    }
                                }
                            },
                            licenses: {
                                type: "keyword",
                            },
                            scope: {
                                type: "keyword",
                            },
                            ecosystem: {
                                type: "keyword",
                                fields: {
                                    text: {
                                        type: "text",
                                    }
                                }
                            }
                        }
                    }
                }
            }
        });
    }

    if (!cdxTemplateExists) {
        console.log('Creating template for sbom');
        putTemplateCalls.push(client.indices.putIndexTemplate({
            name: CDX_TEMPLATE,
            body: {
                priority: 200,
                index_patterns: [`${prefixes.sbom}*`, `raw-${prefixes.sbom}*`],
                template: {
                    settings: {
                        number_of_shards: "1",
                        number_of_replicas: "1"
                    }
                },
                composed_of: [CDX_COMPONENT_TEMPLATE]
            }
        }));
        putTemplateCalls.push(client.indices.putIndexTemplate({
            name: CDX_ALL_TEMPLATE,
            body: {
                priority: 300,
                index_patterns: [`${prefixes.sbom}all-*`],
                template: {
                    settings: {
                        'plugins.index_state_management.rollover_alias': `${prefixes.sbom}all`,
                        number_of_replicas : "5"
                    }
                },
                composed_of: [CDX_COMPONENT_TEMPLATE]
            }
        }));
    }

    if (!advisoriesTemplateExists) {
        console.log('Creating template for advisories');
        putTemplateCalls.push(client.indices.putTemplate({
            name: ADVISORIES_TEMPLATE,
            body: {
                index_patterns: [`${prefixes.advisories}`, `raw-${prefixes.advisories}*`],
                mappings: {
                    properties: {
                        id: {
                            type: "keyword",
                            fields: {
                                text: {
                                    type: "text",
                                }
                            }
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
                            properties: {
                                vendor: {
                                    type: "keyword",
                                    fields: {
                                        text: {
                                            type: "text",
                                        }
                                    }
                                },
                                name: {
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
                                source: {
                                    type: "keyword",
                                    fields: {
                                        text: {
                                            type: "text",
                                        }
                                    }
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
        }));
    }

    if (!vulnerabilitiesComponentTemplateExists) {
        console.log('Creating components for vulnerabilities');
        await client.cluster.putComponentTemplate({
            name: VULNERABILITIES_COMPONENT_TEMPLATE,
            body: {
                template: {
                    mappings: {
                        properties: {
                            id: {
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
                            title: {
                                type: "keyword",
                                fields: {
                                    text: {
                                        type: "text",
                                    }
                                }
                            },
                            severity: {
                                type: "keyword"
                            },
                            package: {
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
                            project: {
                                type: "keyword",
                                fields: {
                                    text: {
                                        type: "text",
                                    }
                                }
                            },
                            repo: {
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
                            hash: {
                                type: "keyword",
                                fields: {
                                    text: {
                                        type: "text",
                                    }
                                }
                            },
                            excluded: {
                                type: "boolean"
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
                    },
                }
            }
        });
    }

    if (!vulnerabilitiesTemplateExists) {
        console.log('Creating template for vulnerabilities');
        putTemplateCalls.push(client.indices.putIndexTemplate({
            name: VULNERABILITIES_TEMPLATE,
            body: {
                priority: 200,
                index_patterns: [`${prefixes.vulnerabilities}*`, `raw-${prefixes.vulnerabilities}*`],
                template: {
                    settings: {
                        number_of_replicas: "1"
                    }
                },
                composed_of: [VULNERABILITIES_COMPONENT_TEMPLATE]
            }
        }));
        putTemplateCalls.push(client.indices.putIndexTemplate({
            name: VULNERABILITIES_ALL_TEMPLATE,
            body: {
                priority: 300,
                index_patterns: [`${prefixes.vulnerabilities}all`],
                template: {
                    settings: {
                        'plugins.index_state_management.rollover_alias': `${prefixes.vulnerabilities}all`,
                        number_of_replicas: "5"
                    }
                },
                composed_of: [VULNERABILITIES_COMPONENT_TEMPLATE]
            }
        }));
    }

    if (!notesTemplateExists) {
        console.log('Creating template for notes');
        putTemplateCalls.push(client.indices.putTemplate({
            name: NOTES_TEMPLATE,
            body: {
                order: 0,
                index_patterns: [`notes`],
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
        }));
    }

    if (!exclusionsTemplateExists) {
        console.log('Creating template for exclusions');
        putTemplateCalls.push(client.indices.putTemplate({
            name: EXCLUSIONS_TEMPLATE,
            body: {
                order: 0,
                index_patterns: [`exclusions`],
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
                    }
                }
            }
        }));
    }

    /*
    PUT _plugins/_ism/policies/rollover_policy
    {
      "policy": {
        "description": "Rollover policy",
        "default_state": "rollover",
        "states": [
          {
            "name": "rollover",
            "actions": [
              {
                "rollover": {
                  "min_doc_count": 100000
                }
              }
            ],
            "transitions": []
          }
        ],
        "ism_template": {
          "index_patterns": ["sbom-all-*", "vulnerabilities-all-*"],
          "priority": 100
        }
      }
    }
     */


    if (!(await aliasExists(`${prefixes.sbom}all`))) {
        await client.indices.create({
            index: `${prefixes.sbom}all-000001`,
            body: {
                aliases: {
                    [`${prefixes.sbom}all`]: {
                        is_write_index: true
                    }
                }
            }
        });
    }

    if (!(await aliasExists(`${prefixes.vulnerabilities}all`))) {
        await client.indices.create({
            index: `${prefixes.vulnerabilities}all-000001`,
            body: {
                aliases: {
                    [`${prefixes.vulnerabilities}all`]: {
                        is_write_index: true
                    }
                }
            }
        });
    }

    if (!(await indexExists('notes'))) {
        await client.indices.create({
            index: 'notes',
        });
    }

    if (!(await indexExists('exclusions'))) {
        await client.indices.create({
            index: 'exclusions',
        });
    }

    await awaitAll(putTemplateCalls);
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
        slices: 'auto'
    });

    console.log(`Deleted ${result.body.deleted}/${result.body.total}`);
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
                console.log(`Deleting old index ${aliasIndex} ... `);
                await client.indices.delete({ index: aliasIndex });
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

const search = async (index, body, size = 100, transform = null, loop = false) => {
    let res = await client.search({
        index,
        body,
        scroll: loop ? '10s' : undefined,
        size
    });
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

    const clearedScrolls = await client.clearScroll({ body: { scroll_id: scrollIds } });
    //if (!clearedScrolls.body.success) console.log('Failed to clear scroll contexts');

    return data;
};

const scroll = async scrollId => {
    return client.scroll({
        body: {
            scroll_id: scrollId,
            scroll: '30s',
        }
    });
}

const containsProject = async (indexName, project) => {
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
    search,
    indexDocs,
    containsProject,
    deleteDocs,
};