const config = require("../config");
const { awaitAll } = require("../awaitAll");
const OpenSearch = require("../opensearch");
const Email = require("../email");


const prefixes = config.get('opensearch.prefixes');
const projects = config.get('projects');

const HIGH_SEVS = ['CRITICAL', 'HIGH', 'MEDIUM'];

const getWeekSummary = week => week.projects.buckets.reduce((result, bucket) => {
    result[bucket.key] = bucket.committed.buckets[0].scanned.buckets[0].severities.buckets.reduce((result, severity) => {
        result[HIGH_SEVS.includes(severity.key) ? 'high' : 'low'] += severity.doc_count;
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

    const getUnknownIndicator = () => `<td></td>`;

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


module.exports = {
    create,
    email
}