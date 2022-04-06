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
        const parts = [];
        const reRange = /(?<=^|,)([(\[])([^)\]]+?)?,([^(\[]+?)?([)\]])(?=,|$)/g;
        let match;
        while ((match = reRange.exec(version)) !== null) {
            const p = [];
            if (match[2]) p.push(translateVersionBoundary[match[1]] + match[2]);
            if (match[3]) p.push(translateVersionBoundary[match[4]] + match[3]);
            parts.push(p.join(' '));
        }

        const reFixed = /(?<=^|,)\[([^)\]]+)\](?=,|$)/g;
        while ((match = reFixed.exec(version)) !== null) {
            if (match[1]) parts.push('=' + match[1]);
        }

        return parts.join(' || ');
    }

    let cleanVersion = version
        .replace(/^(and|reported for)\s+/i, '')
        .replace(/version\s+/i, '')
        .replace(/ver.(\d)/i, '$1')
        .replace(/^([<>]=?)v?(\d)/i, '$1 $2')
        .replace(/^(all( versions)?|Not fixed)$/i, '*')
        .replace(/^v?(\d+(?:[-.][^ ]+)?)$/i, '$1')
        .replace(/^all versions /i, '')
        .replace(/^(all )?(versions )?(before|prior to|up to) v?/i, '<')
        .replace(/^v?(\d.+?) before v?(\d.+?)$/i, '>=$1 <$2')
        .replace(/^v?(\d.+?) and earlier/i, '<=$1')
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
    getAliasName: (project, prefix = 'cdx-', suffix = '') => prefix + normalizeName(project.name) + '~' + normalizeTag(project.tag) + suffix,
    getIndexName: (project, prefix = 'raw-cdx-', suffix = '') => prefix + normalizeName(project.name) + '-' + normalizeTag(project.tag) + '-' + project.hash + suffix,
}