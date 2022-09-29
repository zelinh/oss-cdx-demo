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
        dates: [
            `commit: ${intl.format(new Date(prev.timestamp.commit))}, scan: ${intl.format(new Date(prev.timestamp.scan))}`,
            `commit: ${intl.format(new Date(current.timestamp.commit))}, scan: ${intl.format(new Date(current.timestamp.scan))}`,
        ],
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

const sendWeeklySummary = async (method = 'email') => {
    console.log("Preparing weekly summary ...");
    const changes = await getChanges('now', 7, true);
    const summary = extractSummary(changes);

    await sendSummary(summary, method);
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

    if (news.size === 0) console.log("Nothing new for latest news");
    console.log(`Got ${news.size} news to inform...`);

    await sendNews(news, method);

    console.log("Marking scans as examined...");
    await OpenSearch.markScansAsExamined(filters);
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

const extractSummary = data => {
    const summary = new Map();
    for (const entry of data) {
        summary.set(entry.project, { changes: entry.changes, current: entry.current });
    }

    return new Map([...summary].sort(([a], [b]) => a.localeCompare(b)));
};

const sendSummary = async (summary, method = 'email') => {
    switch (method) {
        case 'slack':
            return await sendSummaryOverSlack(summary);

        case 'email':
            return await sendSummaryOverEmail(summary);
    }
};

const sendNews = async (news, method = 'slack') => {
    switch (method) {
        case 'slack':
            return await sendNewsOverSlack(news);

        case 'email':
            return await sendNewsOverEmail(news);
    }
};

const sendNewsOverSlack = async news => {
    for (const [advisoryId, { impact, severity }] of news) {
        await Slack.send(
            `${HIGH_SEVS.includes(severity) ? ':alert:' : ':warning:' } ${advisoryId}\nhttps://advisories.aws.barahmand.com/advisory/${advisoryId}`,
            `Impacted ${impact.size === 1 ? 'project' : 'projects'}:\n■ ${[...impact.keys()].join('\n■ ')}\n`
        );
    }
};

const sendNewsOverEmail = async news => {};

const sendSummaryOverSlack = async summary => {};

const sendSummaryOverEmail = async summary => {
    const body = [
        `<style>.wrapper{background:#1c222f;padding:20px;font-family:"Gill Sans MT","Trebuchet MS",sans-serif;font-size:14px;color:#d0d2d6}.wrapper a{color:#d0d2d6;text-decoration:none}.wrapper table{table-layout:fixed;font-size:inherit;border-collapse:collapse;border:none}.wrapper th{font-weight:800;font-size:12px;height:30px;text-transform:uppercase;background-color:#3c495e;padding:0 10px;border-bottom:1px solid #a1b0cb;white-space:nowrap}.wrapper td{vertical-align:middle;height:12px;font-size:11px;background-color:#283144;white-space:nowrap}td.right{text-align:right}.down{width:12px;color:rgba(125,245,125,0.75);background:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='green' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='m23 18-9-9-5 5-8-8'/%3E%3Cpath d='M17 18h6v-6'/%3E%3C/svg%3E") 0 3px / 12px 12px no-repeat}.up{width:12px;color:rgba(245,122,122,0.75);background:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='red' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='m23 6-9 10-5-5-8 7'/%3E%3Cpath d='M17 6h6v6'/%3E%3C/svg%3E") 0 3px / 12px 12px no-repeat}.wrapper td[rowspan="2"]{font-size:14px;line-height:25px;padding:10px;border-bottom:1px solid #546990}.wrapper td[rowspan="2"] ~ td.small{padding:5px 5px 1px;background-position:0 6px}.wrapper td[rowspan="2"]:not(:first-child){background-color:#0d182f}.wrapper td.small{padding:1px 5px 5px;color:#a1b0cb}.wrapper td.small:first-child,.wrapper td.small:first-child ~ .small{border-bottom:1px solid #546990}.wrapper td.up[rowspan="2"],.wrapper td.down[rowspan="2"]{width:30px;background-size:20px 20px;background-position:0 13px;padding-left:25px;font-size:12px}</style>`,
        `<body class="wrapper"><div>Below is a summary of the vulnerabilities identified on OpenSearch Project:</div><br><table><tr><th style="text-align: left;">Project</th><th colspan="2">Was</th><th colspan="2">This Week</th><th colspan="2">Vulnerabilities</th></tr>`
    ];

    for (const [project, { current, changes }] of summary) {
        body.push(`<tr><td rowspan="2"><a href="https://advisories.aws.barahmand.com/vulnerabilities/${encodeURI(project)}/origin/main">${project}</a></td><td class="small">Severe:</td><td class="small right">${current.severe - changes.severe}</td><td class="small right">${current.severe}</td><td class="small ${changes.severe > 0 ? 'up' : changes.severe < 0 ? 'down' : ''}"></td><td rowspan="2" class="right">${current.total}</td><td rowspan="2" class="${changes.total > 0 ? 'up' : changes.total < 0 ? 'down' : ''}">${changes.total > 0 ? changes.total : changes.total < 0 ? -changes.total : ''}</td></tr><tr><td class="small">Minor:</td><td class="small right">${current.minor - changes.minor}</td><td class="small right">${current.minor}</td><td class="small ${changes.minor > 0 ? 'up' : changes.minor < 0 ? 'down' : ''}"></td></tr>`);
    }

    body.push(`</table></body>`);

    const date = new Date();
    date.setDate(date.getDate() - date.getDay() + 1);
    const weekString = date.toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });

    console.log(`Sending email for the week of ${weekString} ...`);

    await Email.send(`Vulnerabilities for the week of ${weekString}`, body.join(''));
};

module.exports = {
    create,
    email,
    sendWeeklySummary,
    sendLatestNews
}