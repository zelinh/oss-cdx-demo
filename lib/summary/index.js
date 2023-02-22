const ExcelJS = require('exceljs');
const config = require("../config");
const { awaitAll } = require("../awaitAll");
const OpenSearch = require("../opensearch");
const Email = require("../email");
const Slack = require("../slack");
const constants = require("../vulnerabilities/constants");
const { HIGH_SEVS } = require("../vulnerabilities/constants");
const fs = require("fs");
const path = require("path");

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

const getChanges = async (timestamp = Date.now(), daysApart = 1, limitedToTag) => {
    const dateSeparator = timestamp.includes?.('now') ? '' : '||';
    const gap = daysApart > 1 ? `-${daysApart - 1}d` : '';
    const queryOnlyATag = limitedToTag
        ? [{ term: { 'project.tag': { value: limitedToTag === true ? 'origin/main' : limitedToTag } } }]
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
                        ...queryOnlyATag
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
                        ...queryOnlyATag
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

const getLatestChanges = async (limitedToTag) => {
    const queryMainTag = {};
    const queryExaminedMainTag = { query: { bool: { filter: [{ term: { examined: true } }] } } };
    if (limitedToTag) {
        queryExaminedMainTag.query.bool.filter.push({ term: { 'project.tag': { value: limitedToTag === true ? 'origin/main' : limitedToTag } } });
        queryMainTag.query = { bool: { filter: [{ term: { 'project.tag': { value: limitedToTag === true ? 'origin/main' : limitedToTag } } }] } };
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

const sendWeeklySummary = async (method = 'email', limitedToTag = 'origin/main') => {
    console.log("Preparing weekly summary ...");
    const changes = await getChanges('now', 7, limitedToTag);
    const summary = extractSummary(changes);

    await sendSummary(summary, method);
};

const sendLatestNews = async (method = 'slack') => {
    console.log("Preparing latest news ...");
    const latestChanges = await getLatestChanges();
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
    console.log("Marked scans as examined...");
    console.log('latestChanges:', JSON.stringify(latestChanges));
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
        console.log(entry.project, entry.dates);
    }

    return new Map([...summary].sort(([a], [b]) => a.localeCompare(b)));
};

const sendSummary = async (summary, method = 'email') => {
    switch (method) {
        case 'slack':
            return await sendSummaryOverSlack(summary);

        case 'email':
            return await sendSummaryOverEmail(summary);

        case 'excel':
            return await sendSummaryAsExcel(summary);
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
        //`<style>.wrapper{background:#1c222f;padding:20px;font-family:"Gill Sans MT","Trebuchet MS",sans-serif;font-size:14px;color:#d0d2d6}.wrapper a{color:#d0d2d6;text-decoration:none}.wrapper table{table-layout:fixed;font-size:inherit;border-collapse:collapse;border:none}.wrapper th{font-weight:800;font-size:12px;height:30px;text-transform:uppercase;background-color:#3c495e;padding:0 10px;border-bottom:1px solid #a1b0cb;white-space:nowrap}.wrapper td{vertical-align:middle;height:12px;font-size:11px;background-color:#283144;white-space:nowrap}td.right{text-align:right}.down{width:12px;color:rgba(125,245,125,0.75);background:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='green' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='m23 18-9-9-5 5-8-8'/%3E%3Cpath d='M17 18h6v-6'/%3E%3C/svg%3E") 0 3px / 12px 12px no-repeat}.up{width:12px;color:rgba(245,122,122,0.75);background:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='red' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='m23 6-9 10-5-5-8 7'/%3E%3Cpath d='M17 6h6v6'/%3E%3C/svg%3E") 0 3px / 12px 12px no-repeat}.wrapper td[rowspan="2"]{font-size:14px;line-height:25px;padding:10px;border-bottom:1px solid #546990}.wrapper td[rowspan="2"] ~ td.small{padding:5px 5px 1px;background-position:0 6px}.wrapper td[rowspan="2"]:not(:first-child){background-color:#0d182f}.wrapper td.small{padding:1px 5px 5px;color:#a1b0cb}.wrapper td.small:first-child,.wrapper td.small:first-child ~ .small{border-bottom:1px solid #546990}.wrapper td.up[rowspan="2"],.wrapper td.down[rowspan="2"]{width:30px;background-size:20px 20px;background-position:0 13px;padding-left:25px;font-size:12px}</style>`,
        `<style>
            .wrapper{background:#1c222f;padding:20px;font-family:"Gill Sans MT","Trebuchet MS",sans-serif;font-size:14px;color:#d0d2d6}
            .wrapper a{color:#d0d2d6;text-decoration:none}
            .wrapper table{table-layout:fixed;font-size:inherit;border-collapse:collapse;border:none}
            .wrapper th{font-weight:800;font-size:12px;height:30px;text-transform:uppercase;background-color:#3c495e;padding:0 10px;border-bottom:1px solid #a1b0cb;white-space:nowrap}
            .wrapper td{vertical-align:middle;height:12px;font-size:11px;background-color:#283144;white-space:nowrap}
            td.right{text-align:right}
            td.center{text-align:center}
            .down{width:12px;color:rgba(125,245,125,0.75)}
            .up{width:12px;color:rgba(245,122,122,0.75)}
            .wrapper td[rowspan="2"]{font-size:14px;line-height:25px;padding:10px;border-bottom:1px solid #546990}
            .wrapper td[rowspan="2"] ~ td.small{padding:5px 5px 1px;background-position:0 6px}
            .wrapper td[rowspan="2"]:not(:first-child){background-color:#0d182f}
            .wrapper td.small{padding:1px 5px 5px;color:#a1b0cb}
            .wrapper td.small:first-child,.wrapper td.small:first-child ~ .small{border-bottom:1px solid #546990}
            .wrapper td.up[rowspan="2"],.wrapper td.down[rowspan="2"]{background-size:20px 20px;background-position:0 13px;font-size:12px}
            .wrapper td.up.right[rowspan="2"],.wrapper td.down.right[rowspan="2"]{width:30px;padding-right:0}
            .wrapper td.up[rowspan="2"]:last-child,.wrapper td.down[rowspan="2"]:last-child{padding-left:5px}
         </style>`,
        `<body class="wrapper"><div>Below is a summary of the vulnerabilities identified on OpenSearch Project:</div><br><table><tr><th style="text-align: left;">Project</th><th colspan="2">Was</th><th colspan="2">This Week</th><th colspan="3">Vulnerabilities</th></tr>`
    ];

    let usedImage = { up: false, down: false };

    for (const [project, { current, changes }] of summary) {
        if (changes.severe > 0 || changes.minor > 0 || changes.total > 0) usedImage.up = true;
        if (changes.severe < 0 || changes.minor < 0 || changes.total < 0) usedImage.down = true;
        body.push(`<tr><td rowspan="2"><a href="https://advisories.aws.barahmand.com/vulnerabilities/${encodeURI(project)}/origin/main">${project}</a></td><td class="small">Severe:</td><td class="small right">${current.severe - changes.severe}</td><td class="small right">${current.severe}</td><td class="small ${changes.severe > 0 ? 'up' : changes.severe < 0 ? 'down' : ''}">${changes.severe === 0 ? '' : `<img src="cid:${changes.severe > 0 ? 'up' : 'down'}@trend" width="12" />`}</td><td rowspan="2" class="center">${current.total}</td><td rowspan="2" class="right ${changes.total > 0 ? 'up' : changes.total < 0 ? 'down' : ''}">${changes.total === 0 ? '' : `<img src="cid:${changes.total > 0 ? 'up' : 'down'}@trend" width="20" />`}</td><td rowspan="2" class="${changes.total > 0 ? 'up' : changes.total < 0 ? 'down' : ''}">${changes.total > 0 ? changes.total : changes.total < 0 ? -changes.total : ''}</td></tr><tr><td class="small">Minor:</td><td class="small right">${current.minor - changes.minor}</td><td class="small right">${current.minor}</td><td class="small ${changes.minor > 0 ? 'up' : changes.minor < 0 ? 'down' : ''}">${changes.minor === 0 ? '' : `<img src="cid:${changes.minor > 0 ? 'up' : 'down'}@trend" width="12" />`}</td></tr>`);
    }

    body.push(`</table></body>`);

    const date = new Date();
    date.setDate(date.getDate() - date.getDay() + 1);
    const weekString = date.toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });

    console.log(`Sending email for the week of ${weekString} ...`);

    const attachments = [];
    if (usedImage.up) attachments.push({
        filename: 'up-60x60.png',
        path: './assets/up-60x60.png',
        cid: 'up@trend'
    });
    if (usedImage.down) attachments.push({
        filename: 'down-60x60.png',
        path: './assets/down-60x60.png',
        cid: 'down@trend'
    });

    attachments.push({
        filename: `Weekly-Vulnerabilities-Report-${weekString.replace(/[^a-z0-9]+/ig, '-')}.xlsx`,
        content: await generateExcelSummary(summary)
    });

    await Email.send(`Vulnerabilities for the week of ${weekString}`, body.join(''), attachments);
};

const sendSummaryAsExcel = async summary => {
    await generateExcelSummary(summary, '.');
};

const generateExcelSummary = async (summary, dest) => {
    console.log(`Generating Excel summary ...`);
    const workbook = new ExcelJS.Workbook();
    workbook.creator = 'OpenSearch Advisories';

    const imgDownSmall = workbook.addImage({
        buffer: fs.readFileSync('./assets/down-12x12.png'),
        extension: 'png',
    });

    const imgDownMedium = workbook.addImage({
        buffer: fs.readFileSync('./assets/down-20x20.png'),
        extension: 'png',
    });

    const imgUpSmall = workbook.addImage({
        buffer: fs.readFileSync('./assets/up-12x12.png'),
        extension: 'png',
    });

    const imgUpMedium = workbook.addImage({
        buffer: fs.readFileSync('./assets/up-20x20.png'),
        extension: 'png',
    });

    const date = new Date();
    date.setDate(date.getDate() - date.getDay() + 1);
    const weekString = date.toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });

    const worksheet = workbook.addWorksheet(weekString);
    worksheet.getColumn(1).width = 40.83;
    worksheet.getColumn(2).width = 8.83;
    worksheet.getColumn(3).width = 8.83;
    worksheet.getColumn(4).width = 8.83;
    worksheet.getColumn(5).width = 11.83;
    worksheet.getColumn(6).width = 9.83;

    let rowNum = 1;
    for (const [project, { current, changes }] of summary) {
        const row1 = worksheet.getRow(rowNum);
        const row2 = worksheet.getRow(rowNum + 1);
        worksheet.mergeCells(rowNum,1,rowNum + 1,1);
        row1.getCell(1).value = project;
        row1.getCell(1).alignment = { vertical: 'middle', horizontal: 'left' };

        row1.getCell(2).value = 'Severe:';
        row1.getCell(2).alignment = { vertical: 'middle', horizontal: 'right' };
        row2.getCell(2).value = 'Minor:';
        row2.getCell(2).alignment = { vertical: 'middle', horizontal: 'right' };

        row1.getCell(3).value = current.severe - changes.severe;
        row1.getCell(3).alignment = { vertical: 'middle', horizontal: 'center' };
        row2.getCell(3).value = current.minor - changes.minor;
        row2.getCell(3).alignment = { vertical: 'middle', horizontal: 'center' };

        row1.getCell(4).value = current.severe;
        row1.getCell(4).alignment = { vertical: 'middle', horizontal: 'center' };
        row2.getCell(4).value = current.minor;
        row2.getCell(4).alignment = { vertical: 'middle', horizontal: 'center' };

        worksheet.mergeCells(rowNum,5,rowNum + 1, 5);
        row1.getCell(5).value = current.total;
        row1.getCell(5).alignment = { vertical: 'middle', horizontal: 'center' };

        if (changes.total !== 0) {
            worksheet.mergeCells(rowNum, 6, rowNum + 1, 6);
            row1.getCell(6).value = Math.abs(changes.total);
            row1.getCell(6).alignment = { vertical: 'middle', horizontal: 'center' };
        }

        if (changes.severe < 0) {
            worksheet.addImage(imgDownSmall, {
                tl: { col: 3.75, row: rowNum - .75 },
                ext: { width: 12, height: 12 }
            });
        } else if (changes.severe > 0) {
            worksheet.addImage(imgUpSmall, {
                tl: { col: 3.75, row: rowNum - .75 },
                ext: { width: 12, height: 12 }
            });
        }

        if (changes.minor < 0) {
            worksheet.addImage(imgDownSmall, {
                tl: { col: 3, row: rowNum + 1 },
                ext: { width: 12, height: 12 }
            });
        } else if (changes.minor > 0) {
            worksheet.addImage(imgUpSmall, {
                tl: { col: 3, row: rowNum + 1 },
                ext: { width: 12, height: 12 }
            });
        }

        if (changes.total) {
            if (changes.total < 0) {
                worksheet.addImage(imgDownMedium, {
                    tl: { col: 5.15, row: rowNum - .5 },
                    ext: { width: 20, height: 20 }
                });
                row1.getCell(6).font = { color: { argb: 'c0008000' } };
            } else if (changes.total > 0) {
                worksheet.addImage(imgUpMedium, {
                    tl: { col: 5.15 , row: rowNum - .5 },
                    ext: { width: 20, height: 20 }
                });
                row1.getCell(6).font = { color: { argb: 'c0ff0000' } };
            }
        }


        row1.commit();
        rowNum += 2;
    }

    if (dest) {
        const file = path.join(dest, `weekly-report-${weekString}.xlsx`);
        await workbook.xlsx.writeFile(file);
        return file;
    }

    return await workbook.xlsx.writeBuffer();
};

module.exports = {
    create,
    email,
    sendWeeklySummary,
    sendLatestNews
}