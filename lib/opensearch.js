const config = require('./config');
const { Client } = require('@opensearch-project/opensearch');
const { normalize } = require("./normalizer");

const client = new Client({
    node: config.get('opensearch.domain.endpoint'),
    auth: config.get('opensearch.auth'),
    compression: 'gzip',
});

const prefixes = config.get('opensearch.prefixes');
const BULK_LIMIT = config.get('opensearch.limits.bulk') || 10000;

const awaitAll = async awaitCalls => {
    const results = [];
    for (const awaitCall of awaitCalls) {
        results.push(await awaitCall);
    }

    return results;
}

const initIndices = async () => {
    const CDX_TEMPLATE = `${prefixes.cdx}template`;
    const ADVISORIES_TEMPLATE = `${prefixes.advisories}template`;
    const VULNERABILITIES_TEMPLATE = `${prefixes.vulnerabilities}template`;

    const [
        { body: cdxTemplateExists },
        { body: advisoriesTemplateExists },
        { body: vulnerabilitiesTemplateExists },
    ] = await awaitAll([
        client.indices.existsTemplate({ name: CDX_TEMPLATE }),
        client.indices.existsTemplate({ name: ADVISORIES_TEMPLATE }),
        client.indices.existsTemplate({ name: VULNERABILITIES_TEMPLATE }),
    ]);

    const putTemplateCalls = [];
    if (!cdxTemplateExists) {
        console.log('Creating template for cdx');
        putTemplateCalls.push(client.indices.putTemplate({
            name: CDX_TEMPLATE,
            body: {
                index_patterns: [`${prefixes.cdx}*`, `raw-${prefixes.cdx}*`],
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

    if (!vulnerabilitiesTemplateExists) {
        console.log('Creating template for vulnerabilities');
        putTemplateCalls.push(client.indices.putTemplate({
            name: VULNERABILITIES_TEMPLATE,
            body: {
                index_patterns: [`${prefixes.vulnerabilities}*`, `raw-${prefixes.vulnerabilities}*`],
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
                            },
                        },
                        project: {
                            properties: {
                                name: {
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
                            },
                        },
                        timestamp: {
                            type: "date"
                        }
                    }
                }
            }
        }));
    }

    await awaitAll(putTemplateCalls);
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

const indexExists = async name => {
    const { body } = await client.indices.exists({ index: name });
    return body;
};

const pointAlias = async (name, index) => {
    console.log(`Checking if alias ${name} exists...`);
    const { body: aliasExists } = await client.indices.existsAlias({ name, ignore_unavailable: true });

    let aliasExistsAndIsPointingToIndex = false;
    if (aliasExists) {
        console.log(`Getting alias ${name} ...`);
        const { body: resGetAlias } = await client.indices.getAlias({ name });
        const indices = Object.keys(resGetAlias);
        for await (let aliasIndex of indices) {
            if (aliasIndex === index) {
                aliasExistsAndIsPointingToIndex = true;
            } else {
                console.log(`Deleting alias ${name} ...`);
                await client.indices.deleteAlias({ name, index: aliasIndex });
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

    const clearedScrolls = await client.clearScroll({ scroll_id: scrollIds });
    //if (!clearedScrolls.body.success) console.log('Failed to clear scroll contexts');

    return data;
};

const scroll = async scrollId => {
    return client.scroll({
        scroll_id: scrollId,
        scroll: '30s'
    });
}

const containsProject = async project => {
    const indexName = 'raw-cdx-' + normalize.name(project.name) + '-*';
    const res = await client.search({
        index: indexName,
        body: {
            query: {
                bool: {
                    must: [
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

module.exports = {
    initIndices,
    indexExists,
    pointAlias,
    getUniques,
    search,
    indexDocs,
    containsProject,
};