const numericMatcher = /^\d+$/;
const releaseSegmentMatcher = /^(\d*)(a(?:lpha)?|b(?:eta)?|r?c|m|incubating|next|pre(?:view)?|build|u|post|r(?:ev)?|v|dev)(\d*)$/i;
const localLabelMatcher = /^(\d*)\+(.+?)(\d*)$/;
const wildcardSegmentMatcher = /^(\d*)([*+])$/;
const hashSegmentMatcher = /^[0-9a-f]{12}$/;
const dateSegmentMatcher = /^(19|20)\d{2}(0[1-9]|1[0-2])(0[1-9]|[1-2]\d|3[01])(([0-5]\d){3})?$/;
const throwAwayMatcher = /[._-](ga|empty-to-avoid-conflict-with-guava|final|release)$/i;
const knownLabelMatcher = /^(jre|kibana|snapshot|groovy|security|android|canary)(\d*)$/i;
const unFlaggedLabelMatcher = /^(\w+?)(\d*)$/;

/* From
 * PEP 440: https://peps.python.org/pep-0440/#pre-release-spelling
 */
const normalizedSegments = new Map([
    ['dev', 'dev'],
    ['a', 'alpha'],
    ['alpha', 'alpha'],
    ['b', 'beta'],
    ['beta', 'beta'],
    ['rc', 'rc'],
    ['c', 'rc'],
    ['pre', 'rc'],
    ['preview', 'rc'],
    ['m', 'rc'], // eclipse-collections
    ['incubating', 'rc'], // htrace-core4
    ['next', 'rc'],
    ['u', 'build'], // adoptopenjdk_8
    ['build', 'build'],
    ['post', 'post'],
    ['r', 'post'],
    ['v', 'post'],
    ['rev', 'post'],
]);

const preSegments = new Set(['dev', 'alpha', 'beta', 'rc']);
const postSegments = new Set(['build', 'post']);
const normalSegments = new Set(normalizedSegments.values());

class Version {
    #parts = {
        main: [],
        tag: [],
        label: []
    };

    constructor(v) {
        this.#parse(v);
    }

    #parse(v) {
        const tokens = Version.#tokenize(v);
        let part = 'main';
        tokens.forEach(token => {
            if (part === 'main' && token.type === 'tag') part = 'tag';
            else if (token.type === 'label') part = 'label';

            this.#parts[part].push(token.type ? token.value : token);
        });
    }

    toJSON() {
        return this.#parts;
    }

    toString() {
        return [
            this.#parts.main.length ? this.#parts.main.join('.') : '0.0.0',
            this.#parts.tag.length ? this.#parts.tag.join('.') : [],
            this.#parts.label.length ? this.#parts.label.join('.') : [],
        ].flat().join('-');
    }

    compare() {

    }

    static #tokenize(v) {
        const dateBasedIndices = [];
        return v
            .replace(/^\s*v\s*/, '')
            .replace(throwAwayMatcher, '')
            .split(/[._-]+/)
            .flatMap(
                /**
                 * @param {string} token
                 * @param {number} idx
                 */
                (token, idx) => {
                    const res = [];
                    let match;

                    if ((match = dateSegmentMatcher.exec(token)) !== null) {
                        dateBasedIndices.push(idx);
                        return token;
                    }

                    if ((match = hashSegmentMatcher.exec(token)) !== null) {
                        // A hash after a date is toss-away
                        if (dateBasedIndices.includes(idx - 1)) return [];
                    }

                    if (numericMatcher.test(token)) return parseInt(token, 10);

                    if ((match = releaseSegmentMatcher.exec(token)) !== null) {
                        if (match[1]) res.push(parseInt(match[1], 10));
                        res.push({type: 'tag', value: Version.#normalizeToken(match[2])});
                        if (match[3]) res.push(parseInt(match[3], 10));
                        return res;
                    }

                    if ((match = localLabelMatcher.exec(token)) !== null) {
                        if (match[1]) res.push(parseInt(match[1], 10));
                        res.push({type: 'label', value: match[2]});
                        if (match[3]) res.push(parseInt(match[3], 10));
                        return res;
                    }

                    if ((match = wildcardSegmentMatcher.exec(token)) !== null) {
                        return [
                            parseInt(match[1], 10) || 0,
                            match[2]
                        ];
                    }

                    if ((match = unFlaggedLabelMatcher.exec(token)) !== null) {
                        res.push({type: 'label', value: match[1]});
                        if (match[2]) res.push(parseInt(match[2], 10));
                        return res;
                    }

                    return [];
                }
            );
    }

    static #normalizeToken(token) {
        const lcToken = token?.toLowerCase?.().trim();
        return normalizedSegments.get(lcToken) || lcToken;
    }

    static from(v) {
        return new Version(v);
    }
}

module.exports = Version;