const config = require("../config");
const { awaitAll } = require("../awaitAll");
const OpenSearch = require("../opensearch");
const Email = require("../email");
const Slack = require("../slack");
const constants = require("../vulnerabilities/constants");
const { HIGH_SEVS } = require("../vulnerabilities/constants");

const indices = config.get('opensearch.indices');
const prefixes = config.get('opensearch.prefixes');
const projects = config.get('projects');

const intl = Intl.DateTimeFormat('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
    hour: 'numeric',
    minute: 'numeric',
});

const getWeekSummary = week => week.projects.buckets.reduce((result, bucket) => {
    result[bucket.key] = bucket.committed.buckets[0].scanned.buckets[0].severities.buckets.reduce((result, severity) => {
        result[constants.HIGH_SEVS.includes(severity.key) ? 'high' : 'low'] += severity.doc_count;
        return result;
    }, { high: 0, low: 0, date: bucket.committed.buckets[0].key_as_string });
    return result;
}, {});

const create = async () => {
    console.log('Creating weekly summary ...');
    const [currentWeek, previousWeek, olderWeek] = await awaitAll([
        OpenSearch.getAggregates(`${prefixes.vulnerabilities}all`, {
            aggs: {
                projects: {
                    terms: {
                        field: "project",
                        size: 10000
                    },
                    aggs: {
                        committed: {
                            terms: {
                                field: 'timestamp.commit',
                                size: 1,
                                order: { _key: 'desc' }
                            },
                            aggs: {
                                scanned: {
                                    terms: {
                                        field: 'timestamp.scan',
                                        size: 1,
                                        order: { _key: 'desc' }
                                    },
                                    aggs: {
                                        severities: {
                                            terms: {
                                                field: 'severity',
                                                missing: 'UNDEFINED'
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            },
            query: {
                bool: {
                    filter: [
                        { range: { 'timestamp.commit': { gte: 'now/w' } } },
                        { term: { tag: { value: 'origin/main' } } },
                        { bool: { must_not: { match: { excluded: true } } } },
                    ]
                }
            }
        }),
        OpenSearch.getAggregates(`${prefixes.vulnerabilities}all`, {
            aggs: {
                projects: {
                    terms: {
                        field: "project",
                        size: 10000,
                    },
                    aggs: {
                        committed: {
                            terms: {
                                field: 'timestamp.commit',
                                size: 1,
                                order: { _key: 'asc' }
                            },
                            aggs: {
                                scanned: {
                                    terms: {
                                        field: 'timestamp.scan',
                                        size: 1,
                                        order: { _key: 'desc' }
                                    },
                                    aggs: {
                                        severities: {
                                            terms: {
                                                field: 'severity',
                                                missing: 'UNDEFINED'
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            },
            query: {
                bool: {
                    filter: [
                        { range: { 'timestamp.commit': { gte: 'now-1w/w', lt: 'now/w' } } },
                        { term: { tag: { value: 'origin/main' } } },
                        { bool: { must_not: { match: { excluded: true } } } },
                    ]
                }
            }
        }),
        OpenSearch.getAggregates(`${prefixes.vulnerabilities}all`, {
            aggs: {
                projects: {
                    terms: {
                        field: "project",
                        size: 10000,
                    },
                    aggs: {
                        committed: {
                            terms: {
                                field: 'timestamp.commit',
                                size: 1,
                                order: { _key: 'desc' }
                            },
                            aggs: {
                                scanned: {
                                    terms: {
                                        field: 'timestamp.scan',
                                        size: 1,
                                        order: { _key: 'desc' }
                                    },
                                    aggs: {
                                        severities: {
                                            terms: {
                                                field: 'severity',
                                                missing: 'UNDEFINED'
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            },
            query: {
                bool: {
                    filter: [
                        { range: { 'timestamp.commit': { lt: 'now/w' } } },
                        { term: { tag: { value: 'origin/main' } } },
                        { bool: { must_not: { match: { excluded: true } } } },
                    ]
                }
            }
        })
    ]);

    const currentWeekSummary = getWeekSummary(currentWeek);
    const previousWeekSummary = getWeekSummary(previousWeek);
    const olderWeekSummary = getWeekSummary(olderWeek);

    const result = {};
    for (const project of projects) {
        if (project.disabled) continue;
        if (!currentWeekSummary[project.name] && !previousWeekSummary[project.name] && !olderWeekSummary[project.name]) continue;

        result[project.name] = {
            currentWeek: currentWeekSummary[project.name],
            previousWeek: previousWeekSummary[project.name] || olderWeekSummary[project.name],
        };
    }

    return result;
};

const email = async () => {
    const summary = await create();
    const body = [
        `<div style="font-family: Verdana, Geneva, sans-serif;">Below is a summary of the vulnerabilities identified on OpenSearch Project:</div><br>`,
        `<table style="font-family: Verdana, Geneva, sans-serif; border-style: none; table-layout: fixed;">`,
        `<tr><th style="font-weight: 600; text-align: left; font-size: small;">Project</th><th colspan="2" style="font-weight: 600; text-align: center; font-size: small;">Severe</th><th colspan="2" style="font-weight: 600; text-align: center; font-size: small;">Minor</th></tr>`,
    ];

    const projectNames = Object.keys(summary);
    projectNames.sort();

    const getChangeIndicator = (previousValue, currentValue) => {
        /*
        return currentValue > previousValue
            ? `<td style="font-family: 'Segoe UI Symbol', 'Apple Symbols'; color: #ef233c; font-size: large; width: 15px; padding: 0; line-height: 1; vertical-align: bottom;">&#9650;</td><td style="color: #ef233c; vertical-align: top; font-size: x-small; padding: 0">+${currentValue - previousValue}</td>`
            : currentValue < previousValue
                ? `<td style="font-family: 'Segoe UI Symbol', 'Apple Symbols'; color: #2ec4b6; font-size: large; width: 15px; padding: 0; line-height: 1; vertical-align: bottom;">&#9660;</td><td style="color: #2ec4b6; vertical-align: top; font-size: x-small; padding: 0">${currentValue - previousValue}</td>`
                : `<td colspan="2"></td>`;
         */
        return currentValue > previousValue
            ? `<td style="color: #ef233c; vertical-align: top; font-size: x-small; padding: 0"><span style="font-family: 'Segoe UI Symbol', 'Apple Symbols'; font-size: small;">&#9650;</span>${currentValue - previousValue}</td>`
            : currentValue < previousValue
                ? `<td style="color: #2ec4b6; vertical-align: top; font-size: x-small; padding: 0"><span style="font-family: 'Segoe UI Symbol', 'Apple Symbols'; font-size: small;">&#9660;</span>${previousValue - currentValue}</td>`
                : `<td style="color: #666666; vertical-align: top; font-size: x-small; padding: 0"><span style="font-family: 'Segoe UI Symbol', 'Apple Symbols'; font-size: medium;">&#61;</span></td>`;
    };

    //const getUnknownIndicator = () => `<td></td>`;
    const getUnknownIndicator = () => `<td style="color: #666666; vertical-align: top; font-size: x-small; padding: 0"><span style="font-family: 'Segoe UI Symbol', 'Apple Symbols'; font-size: medium;">&#61;</span></td>`;

    const getRelativeSummaryForProject = name => {
        if (summary[name].currentWeek) {
            return {
                severe: {
                    count: summary[name].currentWeek.high,
                    change: getChangeIndicator(summary[name].previousWeek?.high || 0, summary[name].currentWeek.high)
                },
                minor: {
                    count: summary[name].currentWeek.low,
                    change: getChangeIndicator(summary[name].previousWeek?.low || 0, summary[name].currentWeek.low)
                }
            };
        }
        if (summary[name].previousWeek) {
            return {
                severe: {
                    count: summary[name].previousWeek.high,
                    change: getUnknownIndicator()
                },
                minor: {
                    count: summary[name].previousWeek.low,
                    change: getUnknownIndicator()
                }
            }
        }

        return {
            severe: {
                count: '?',
                change: getUnknownIndicator()
            },
            minor: {
                count: '?',
                change: getUnknownIndicator()
            }
        }
    };

    for (const name of projectNames) {
        const { severe, minor } = getRelativeSummaryForProject(name);
        body.push(`<tr><td><a href="https://advisories.aws.barahmand.com/vulnerabilities/${encodeURI(name)}/origin/main">${name}</a></td><td style="text-align: right; padding: 0; width: 2.5em;">${severe.count}</td>${severe.change}<td style="text-align: right; padding: 0; width: 2.5em;">${minor.count}</td>${minor.change}</tr>`);
    }
    body.push(`</table>`);

    const date = new Date();
    date.setDate(date.getDate() - date.getDay() + 1);
    const weekString = date.toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });

    console.log(`Sending email for the week of ${weekString} ...`);

    await Email.send(`Vulnerabilities for the week of ${weekString}`, body.join(''));
}

const parseScanAggregates = data => {
    const map = new Map();
    for (const { key: project, tags: { buckets: tagBuckets } } of data.projects.buckets) {
        const stats = new Map();
        const tags = new Set();
        map.set(project, { tags, stats });
        for (const { key: tag, vulnerabilities: { hits: { hits: [{ _id, _source: { count, timestamp, vulnerabilities = [] }}] }} } of tagBuckets) {
            stats.set(tag, {
                _id,
                count,
                timestamp,
                advisories: vulnerabilities
                    .filter(({excluded}) => !excluded)
                    .map(({aliases, severity}) => ({ aliases, severity }))
            });
            tags.add(tag);
        }
    }

    return map;
};

const parseLatestAggregates = data => {
    const map = new Map();
    for (const { key: project, tags: { buckets: tagBuckets } } of data.projects.buckets) {
        const current = new Map();
        const prev = new Map();
        const tags = new Set();
        map.set(project, { tags, current, prev });

        for (const { key: tag, vulnerabilities: { hits: { hits: [
            { _id: currentId, _source: { count: currentCount, timestamp: currentTimestamp, vulnerabilities: currentVulnerabilities = [] } = {}} = {},
            { _id: prevId, _source: { count: prevCount, timestamp: prevTimestamp, vulnerabilities: prevVulnerabilities = [] } = {}} = {},
        ] = [] } = {} } = {} } of tagBuckets) {
            current.set(tag, {
                _id: currentId,
                count: currentCount,
                timestamp: currentTimestamp,
                advisories: currentVulnerabilities
                    .filter(({excluded}) => !excluded)
                    .map(({aliases, severity}) => ({ aliases, severity }))
            });
            prev.set(tag, {
                _id: prevId,
                count: prevCount,
                timestamp: prevTimestamp,
                advisories: prevVulnerabilities
                    .filter(({excluded}) => !excluded)
                    .map(({aliases, severity}) => ({ aliases, severity }))
            });
            tags.add(tag);
        }
    }

    return map;
};

const diffAggregates = (current = {}, prev = {}) => {
    if (!prev._id && !current._id) return {};
    if (!prev._id) return {
        changes: { ...current.count, total: current.count.minor + current.count.severe },
        current: { ...current.count, total: current.count.minor + current.count.severe },
        timestamp: current.timestamp.scan,
        type: 'NEW'
    };

    if (!current._id || prev.timestamp?.scan > current?.timestamp?.scan) return {
        changes: { minor: 0, severe: 0, total: 0 },
        current: { ...prev.count, total: prev.count.minor + prev.count.severe },
        timestamp: prev.timestamp.scan,
        type: 'STALE'
    };

    if (
        prev.timestamp && current.timestamp && (
            (prev.timestamp.commit > current.timestamp.commit) ||
            (prev.timestamp.commit === current.timestamp.commit && prev.timestamp.scan > current.timestamp.scan)
        )
    ) return {
        changes: { minor: 0, severe: 0, total: 0 },
        current: { ...prev.count, total: prev.count.minor + prev.count.severe },
        timestamp: prev.timestamp.scan,
        type: 'EXAMINED'
    };

    const prevAliases = prev.advisories?.map?.(({ aliases }) => aliases).flat() || [];

    return {
        changes: {
            minor: current.count.minor - prev.count.minor,
            severe: current.count.severe - prev.count.severe,
            total: current.count.minor + current.count.severe - prev.count.minor - prev.count.severe,
        },
        news: Array.from(current.advisories?.reduce?.((res, { aliases, severity }) => {
            if (!aliases.some(alias => prevAliases.includes(alias))) res.add({ id: aliases[0], severity });
            return res
        }, new Set()) || []),
        dates: prev.timestamp.commit === current.timestamp.commit
            ? ['scan', intl.format(new Date(prev.timestamp.scan)), intl.format(new Date(current.timestamp.scan))]
            : ['commit', intl.format(new Date(prev.timestamp.commit)), intl.format(new Date(current.timestamp.commit))],
        current: { ...current.count, total: current.count.minor + current.count.severe },
        timestamp: current.timestamp.scan,
        type: 'FOUND'
    };
};

const getChanges = async (timestamp = Date.now(), daysApart = 1, limitedToMain = false) => {
    const dateSeparator = timestamp.includes?.('now') ? '' : '||';
    const gap = daysApart > 1 ? `-${daysApart - 1}d` : '';
    const queryMainTag = limitedToMain
        ? [{ term: { 'project.tag': { value: 'origin/main' } } }]
        : [];

    const [dayMinusZero, dayMinusOne] = await awaitAll([
        OpenSearch.getAggregates(indices.scans, {
            aggs: {
                projects: {
                    terms: { field: "project.name", order: { _key: 'asc' }, size: 10000 },
                    aggs: {
                        tags: {
                            terms: { field: "project.tag", order: { _key: 'desc' }, size: 10000 },
                            aggs: {
                                vulnerabilities: {
                                    top_hits: {
                                        sort: [
                                            { 'timestamp.commit': { order: 'desc' } },
                                            { 'timestamp.scan': { order: 'desc' } }
                                        ],
                                        _source: { includes: ['count', 'timestamp', 'vulnerabilities.aliases', 'vulnerabilities.excluded', 'vulnerabilities.severity'] },
                                        size: 1
                                    }
                                }
                            }
                        }
                    }
                }
            },
            query: {
                bool: {
                    must: [
                        { range: { 'timestamp.commit': { lt: `${timestamp}${dateSeparator}+1d/d` } } },
                        { range: { 'timestamp.scan': { lt: `${timestamp}${dateSeparator}+1d/d` } } },
                        ...queryMainTag
                    ],
                }
            }
        }),
        OpenSearch.getAggregates(indices.scans, {
            aggs: {
                projects: {
                    terms: { field: "project.name", order: { _key: 'asc' }, size: 10000 },
                    aggs: {
                        tags: {
                            terms: { field: "project.tag", order: { _key: 'desc' }, size: 10000 },
                            aggs: {
                                vulnerabilities: {
                                    top_hits: {
                                        sort: [
                                            { 'timestamp.commit': { order: 'desc' } },
                                            { 'timestamp.scan': { order: 'desc' } }
                                        ],
                                        _source: { includes: ['count', 'timestamp', 'vulnerabilities.aliases', 'vulnerabilities.excluded', 'vulnerabilities.severity'] },
                                        size: 1
                                    }
                                }
                            }
                        }
                    }
                }
            },
            query: {
                bool: {
                    must: [
                        { range: { 'timestamp.commit': { lt: `${timestamp}${dateSeparator}${gap}/d` } } },
                        { range: { 'timestamp.scan': { lt: `${timestamp}${dateSeparator}${gap}/d` } } },
                        ...queryMainTag
                    ],
                }
            }
        }),
    ]);

    const dayMinusZeroProjects = parseScanAggregates(dayMinusZero);
    const dayMinusOneProjects = parseScanAggregates(dayMinusOne);

    const result = [];
    for (const { name, disabled } of projects) {
        if (disabled) continue;

        const dayMinusZeroInfo = dayMinusZeroProjects.get(name);
        const dayMinusOneInfo = dayMinusOneProjects.get(name);

        const tags = new Set([
            ...(dayMinusZeroInfo?.tags || []),
            ...(dayMinusOneInfo?.tags || []),
        ]);

        for (const tag of tags) {
            result.push({
                project: name,
                tag,
                ...diffAggregates(dayMinusZeroInfo?.stats?.get?.(tag), dayMinusOneInfo?.stats?.get?.(tag))
            });
        }
    }

    return result;
};

const getLatestChanges = async (limitedToMain = false) => {
    const queryMainTag = {};
    const queryExaminedMainTag = { query: { bool: { filter: [{ term: { examined: true } }] } } };
    if (limitedToMain) {
        queryExaminedMainTag.query.bool.filter.push({ term: { 'project.tag': { value: 'origin/main' } } });
        queryMainTag.query = { bool: { filter: [{ term: { 'project.tag': { value: 'origin/main' } } }] } };
    }

    const [latestAggregates, latestExaminedAggregates] = await awaitAll([
        OpenSearch.getAggregates(indices.scans, {
            aggs: {
                projects: {
                    terms: { field: "project.name", order: { _key: 'asc' }, size: 10000 },
                    aggs: {
                        tags: {
                            terms: { field: "project.tag", order: { _key: 'desc' }, size: 10000 },
                            aggs: {
                                vulnerabilities: {
                                    top_hits: {
                                        sort: [
                                            { 'timestamp.commit': { order: 'desc' } },
                                            { 'timestamp.scan': { order: 'desc' } }
                                        ],
                                        _source: { includes: ['count', 'timestamp', 'vulnerabilities.aliases', 'vulnerabilities.excluded', 'vulnerabilities.severity'] },
                                        size: 1
                                    }
                                }
                            }
                        }
                    }
                }
            },
            ...queryMainTag
        }),
        OpenSearch.getAggregates(indices.scans, {
            aggs: {
                projects: {
                    terms: { field: "project.name", order: { _key: 'asc' }, size: 10000 },
                    aggs: {
                        tags: {
                            terms: { field: "project.tag", order: { _key: 'desc' }, size: 10000 },
                            aggs: {
                                vulnerabilities: {
                                    top_hits: {
                                        sort: [
                                            { 'timestamp.commit': { order: 'desc' } },
                                            { 'timestamp.scan': { order: 'desc' } }
                                        ],
                                        _source: { includes: ['count', 'timestamp', 'vulnerabilities.aliases', 'vulnerabilities.excluded', 'vulnerabilities.severity'] },
                                        size: 1
                                    }
                                }
                            }
                        }
                    }
                }
            },
            ...queryExaminedMainTag
        }),
    ]);

    const latestProjects = parseScanAggregates(latestAggregates);
    const latestExaminedProjects = parseScanAggregates(latestExaminedAggregates);

    const result = [];
    for (const { name, disabled } of projects) {
        if (disabled) continue;

        const latestInfo = latestProjects.get(name);
        const latestExamined = latestExaminedProjects.get(name);

        const tags = new Set([
            ...(latestInfo?.tags || []),
            ...(latestExamined?.tags || []),
        ]);

        for (const tag of tags) {
            result.push({
                project: name,
                tag,
                ...diffAggregates(latestInfo?.stats?.get?.(tag), latestExamined?.stats?.get?.(tag))
            });
        }
    }

    return result;
};

const sendDailyNews = async (method = 'slack') => {
    console.log("Preparing daily news ...");
    const news = extractNews(await getChanges('now', 1, true));

    if (news.size === 0) {
        console.log("Nothing new for daily news");
        return;
    }
    await sendNews(news, method);
};

const sendLatestNews = async (method = 'slack') => {
    console.log("Preparing latest news ...");
    const latestChanges = await getLatestChanges(false);
    const news = extractNews(latestChanges);

    const filters = [];
    for (const {project, tag, timestamp} of latestChanges) {
        if (!timestamp) continue;

        filters.push({
            bool: {
                must: [
                    { term: { 'project.name': { value: project } } },
                    { term: { 'project.tag': { value: tag } } },
                    { range: { 'timestamp.scan': { lte: timestamp } } },
                ]
            }
        });
    }
    await OpenSearch.markScansAsExamined(filters);

    if (news.size === 0) {
        console.log("Nothing new for latest news");
        return;
    }
    await sendNews(news, method);
};

const extractNews = data => {
    const newAdvisories = new Map();
    for (const entry of data) {
        if (Array.isArray(entry.news) && entry.news.length) {
            for (const { id, severity } of entry.news) {
                if (newAdvisories.has(id)) {
                    const { impact } = newAdvisories.get(id);
                    if (impact.has(entry.project)) impact.get(entry.project).push(entry.tag);
                    else impact.set(entry.project, [entry.tag]);
                } else {
                    newAdvisories.set(id, { severity, impact: new Map([[entry.project, [entry.tag]]]) });
                }
            }
        }
    }
    
    return newAdvisories;
};

const sendNews = async (news, method = 'slack') => {
    switch (method) {
        case 'slack':
            return await sendNewsOverSlack(news);

        case 'email':
            return await sendNewsOverEmail(news);
    }
}

const sendNewsOverSlack = async news => {
    for (const [advisoryId, { impact, severity }] of news) {
        await Slack.send(
            `${HIGH_SEVS.includes(severity) ? ':alert:' : ':warning:' } ${advisoryId}\nhttps://advisories.aws.barahmand.com/advisory/${advisoryId}`,
            `Impacted ${impact.size === 1 ? 'project' : 'projects'}:\n■ ${[...impact.keys()].join('\n■ ')}\n`
        );
    }
};

const sendNewsOverEmail = async news => {};

module.exports = {
    create,
    email,
    sendDailyNews,
    sendLatestNews
}