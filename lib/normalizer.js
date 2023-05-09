const config = require("./config");
const normalizeName = name => name.toLowerCase().replace(/['"]+/g, '').replace(/[^a-z0-9]+/g, '-');
const normalizeTag = tag => tag.replace(/[\/\\]+/g, '-');

const translateVersionBoundary = {
    '(': '>',
    '[': '>=',
    ')': '<',
    ']': '<=',
};

const normalizeVersion = version => {
    if (!version) return;
    if (/^[(\[].*[)\]]$/.test(version)) {
        const parts = new Set();
        const reRange = /(?<=^|,)([(\[])([^)\]]+?)?,([^(\[]+?)?([)\]])(?=,|$)/g;
        let match;
        while ((match = reRange.exec(version)) !== null) {
            const p = [];
            if (match[2]) p.push(translateVersionBoundary[match[1]] + match[2]);
            if (match[3]) p.push(translateVersionBoundary[match[4]] + match[3]);
            parts.add(p.join(' '));
        }

        const reFixed = /(?<=^|,)\[([^)\]]+)\](?=,|$)/g;
        while ((match = reFixed.exec(version)) !== null) {
            if (match[1]) parts.add('=' + match[1]);
        }

        return Array.from(parts).join(' || ');
    }

    let cleanVersion = version
        .replace(/^(and|reported for)\s+/i, '')
        .replace(/^all\s+(\w+\s+)?versions?\s*/i, '')
        .replace(/^Affected versions[:\s]+/i, '')
        .replace(/versions?\s+/i, '')
        .replace(/ver.(\d)/i, '$1')
        .replace(/(\d)\.x/g, '$1.*')
        .replace(/==/g, '=')
        .replace(/^([<>]=?)v?(\d)/i, '$1$2')
        .replace(/^(all( versions)?|Not fixed)$/i, '*')
        .replace(/^v?(\d+(?:[-.][^ ]+)?)$/i, '$1')
        .replace(/^(all )?(versions )?(before|prior to|up to) and including(\s+v(ersion)?)?\s*/i, '<=')
        .replace(/^(all )?(versions )?(before|prior to|up to)(\s+v(ersion)?)?\s*/i, '<')
        .replace(/^v?(\d.+?) before v?(\d.+?)$/i, '>=$1 <$2')
        .replace(/^(?:[a-z]+\s+)?v?(\d.+?) and (earlier|below|prior)/i, '<=$1')
        .replace(/^fixed in v?/i, '<')
        .replace(/^(through|up to and including|≤) v?/i, '<=')
        .replace(/^(?:all )?(?:versions )?after v?/i, '>')
        .replace(/,\s*(?=[<>])/g, ' ');

    return cleanVersion;
};

const transformSeverity = {
    'NONE': 'UNDEFINED',
    'LOW': 'LOW',
    'MEDIUM': 'MEDIUM',
    'MODERATE': 'MEDIUM',
    'HIGH': 'HIGH',
    'CRITICAL': 'CRITICAL',
};

const normalizeSeverity = severity => {
    return severity ? transformSeverity[severity.toUpperCase()] : 'UNDEFINED';
};

const transformEcosystem = {
    'rubygems': 'gem',
    'crates': 'crates.io'
};

const normalizeEcosystem = ecosystem => {
    const _ecosystem = ecosystem.toLowerCase();
    return transformEcosystem[_ecosystem] || _ecosystem;
};

module.exports = {
    normalize: {
        name: normalizeName,
        tag: normalizeTag,
        version: normalizeVersion,
        severity: normalizeSeverity,
        ecosystem: normalizeEcosystem
    },
}
