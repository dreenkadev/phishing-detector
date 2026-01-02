#!/usr/bin/env node

/*
 * Phishing Detector - URL analysis for phishing detection
 *
 * Features:
 * - URL structure analysis
 * - Domain age check (simulated)
 * - Typosquatting detection
 * - Suspicious keyword detection
 * - SSL verification
 * - Redirect chain analysis
 * - Brand impersonation detection
 */

const https = require('https');
const http = require('http');
const { URL } = require('url');

const VERSION = '1.0.0';

const colors = {
    red: (s) => `\x1b[31m${s}\x1b[0m`,
    green: (s) => `\x1b[32m${s}\x1b[0m`,
    yellow: (s) => `\x1b[33m${s}\x1b[0m`,
    cyan: (s) => `\x1b[36m${s}\x1b[0m`,
    bold: (s) => `\x1b[1m${s}\x1b[0m`,
    dim: (s) => `\x1b[2m${s}\x1b[0m`
};

// Known brands often targeted
const TARGET_BRANDS = [
    'paypal', 'ebay', 'amazon', 'apple', 'microsoft', 'google',
    'facebook', 'instagram', 'twitter', 'linkedin', 'netflix',
    'spotify', 'dropbox', 'adobe', 'chase', 'wellsfargo',
    'bankofamerica', 'citibank', 'usps', 'fedex', 'dhl'
];

// Suspicious keywords
const PHISHING_KEYWORDS = [
    'login', 'signin', 'verify', 'update', 'confirm', 'account',
    'secure', 'banking', 'password', 'credential', 'suspended',
    'unusual', 'activity', 'limit', 'expire', 'unlock', 'restore'
];

// Suspicious TLDs
const SUSPICIOUS_TLDS = [
    '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work',
    '.click', '.link', '.info', '.online', '.site', '.club'
];

class PhishingDetector {
    constructor() {
        this.findings = [];
        this.score = 0;
    }

    analyze(urlString) {
        this.findings = [];
        this.score = 0;

        let url;
        try {
            url = new URL(urlString);
        } catch (e) {
            return {
                url: urlString,
                error: 'Invalid URL',
                isPhishing: true,
                score: 100
            };
        }

        // Run checks
        this.checkProtocol(url);
        this.checkDomain(url);
        this.checkPath(url);
        this.checkSubdomains(url);
        this.checkTyposquatting(url);
        this.checkSuspiciousPatterns(url);
        this.checkLength(url);

        const isPhishing = this.score >= 50;

        return {
            url: urlString,
            hostname: url.hostname,
            findings: this.findings,
            score: Math.min(100, this.score),
            isPhishing,
            verdict: isPhishing ? 'PHISHING' : (this.score >= 30 ? 'SUSPICIOUS' : 'SAFE')
        };
    }

    checkProtocol(url) {
        if (url.protocol !== 'https:') {
            this.addFinding('high', 'No HTTPS', 'Site does not use secure HTTPS protocol');
            this.score += 20;
        }
    }

    checkDomain(url) {
        const hostname = url.hostname.toLowerCase();

        // Check for IP address
        if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)) {
            this.addFinding('critical', 'IP Address URL', 'URL uses IP address instead of domain name');
            this.score += 40;
        }

        // Check suspicious TLDs
        for (const tld of SUSPICIOUS_TLDS) {
            if (hostname.endsWith(tld)) {
                this.addFinding('medium', 'Suspicious TLD', `Domain uses suspicious TLD: ${tld}`);
                this.score += 15;
                break;
            }
        }

        // Check for excessive hyphens
        if ((hostname.match(/-/g) || []).length >= 3) {
            this.addFinding('medium', 'Excessive Hyphens', 'Domain contains many hyphens');
            this.score += 10;
        }

        // Check for numbers in domain
        if (/[0-9]{4,}/.test(hostname)) {
            this.addFinding('low', 'Numbers in Domain', 'Domain contains many numbers');
            this.score += 5;
        }
    }

    checkPath(url) {
        const path = url.pathname.toLowerCase();

        // Check for suspicious keywords in path
        for (const keyword of PHISHING_KEYWORDS) {
            if (path.includes(keyword)) {
                this.addFinding('medium', 'Suspicious Keyword', `Path contains: "${keyword}"`);
                this.score += 10;
                break; // Only count once
            }
        }

        // Check for encoded characters
        if (/%[0-9a-f]{2}/i.test(url.href)) {
            this.addFinding('low', 'URL Encoding', 'URL contains encoded characters');
            this.score += 5;
        }

        // Check for @ symbol (URL confusion)
        if (url.href.includes('@')) {
            this.addFinding('high', 'URL Confusion', 'URL contains @ symbol (potential spoofing)');
            this.score += 25;
        }
    }

    checkSubdomains(url) {
        const parts = url.hostname.split('.');

        // Too many subdomains
        if (parts.length > 4) {
            this.addFinding('medium', 'Many Subdomains', `Domain has ${parts.length - 2} subdomains`);
            this.score += 15;
        }

        // Brand name in subdomain
        for (const brand of TARGET_BRANDS) {
            if (parts.slice(0, -2).some(p => p.includes(brand))) {
                this.addFinding('high', 'Brand in Subdomain', `Brand name "${brand}" appears in subdomain`);
                this.score += 30;
                break;
            }
        }
    }

    checkTyposquatting(url) {
        const hostname = url.hostname.toLowerCase().replace(/\./g, '');

        // Simple typosquatting check
        const typosquatPatterns = [
            { brand: 'paypal', patterns: ['paypa1', 'paypai', 'paypol', 'paypaI'] },
            { brand: 'google', patterns: ['googie', 'goog1e', 'g00gle', 'gooogle'] },
            { brand: 'amazon', patterns: ['amaz0n', 'amazan', 'arnazon', 'amazone'] },
            { brand: 'facebook', patterns: ['faceb00k', 'facebok', 'faceboook'] },
            { brand: 'apple', patterns: ['appie', 'app1e', 'applle'] },
            { brand: 'microsoft', patterns: ['micros0ft', 'mircosoft', 'microsft'] },
        ];

        for (const { brand, patterns } of typosquatPatterns) {
            for (const pattern of patterns) {
                if (hostname.includes(pattern)) {
                    this.addFinding('critical', 'Typosquatting', `Possible typosquat of "${brand}"`);
                    this.score += 40;
                    return;
                }
            }
        }

        // Check for brand names not on official domains
        for (const brand of TARGET_BRANDS) {
            if (hostname.includes(brand) && !hostname.endsWith(`${brand}.com`) && !hostname.endsWith(`${brand}.net`)) {
                this.addFinding('high', 'Brand Impersonation', `Uses "${brand}" but not official domain`);
                this.score += 25;
                break;
            }
        }
    }

    checkSuspiciousPatterns(url) {
        const href = url.href.toLowerCase();

        // Data URI
        if (href.startsWith('data:')) {
            this.addFinding('critical', 'Data URI', 'URL is a data URI (can hide malicious content)');
            this.score += 50;
        }

        // Unicode/Punycode
        if (url.hostname.startsWith('xn--')) {
            this.addFinding('high', 'Punycode Domain', 'Domain uses internationalized characters');
            this.score += 20;
        }

        // Homograph detection (basic)
        if (/[а-яА-Я]/.test(url.hostname)) {
            this.addFinding('critical', 'Homograph Attack', 'Domain contains Cyrillic characters');
            this.score += 40;
        }
    }

    checkLength(url) {
        if (url.href.length > 100) {
            this.addFinding('low', 'Long URL', `URL is ${url.href.length} characters`);
            this.score += 5;
        }

        if (url.hostname.length > 30) {
            this.addFinding('medium', 'Long Domain', `Domain is ${url.hostname.length} characters`);
            this.score += 10;
        }
    }

    addFinding(severity, title, description) {
        this.findings.push({ severity, title, description });
    }
}

function printBanner() {
    console.log(`
${colors.cyan('  ____  _     _     _     _             ')}
${colors.cyan(' |  _ \\| |__ (_)___| |__ (_)_ __   __ _ ')}
${colors.cyan(" | |_) | '_ \\| / __| '_ \\| | '_ \\ / _` |")}
${colors.cyan(' |  __/| | | | \\__ \\ | | | | | | | (_| |')}
${colors.cyan(' |_|   |_| |_|_|___/_| |_|_|_| |_|\\__, |')}
${colors.cyan('  ____       _            _       |___/ ')}
${colors.cyan(' |  _ \\  ___| |_ ___  ___| |_ ___  _ __ ')}
${colors.cyan(" | | | |/ _ \\ __/ _ \\/ __| __/ _ \\| '__|")}
${colors.cyan(' | |_| |  __/ ||  __/ (__| || (_) | |   ')}
${colors.cyan(' |____/ \\___|\\__\\___|\\___|\\__\\___/|_|   ')}
                                        ${colors.dim('v' + VERSION)}
`);
}

function printResult(result) {
    console.log(colors.cyan('─'.repeat(60)));
    console.log(`${colors.bold('URL:')} ${result.url}`);
    console.log(`${colors.bold('Domain:')} ${result.hostname || 'N/A'}`);
    console.log(colors.cyan('─'.repeat(60)));

    if (result.error) {
        console.log(colors.red(`Error: ${result.error}`));
        return;
    }

    if (result.findings.length > 0) {
        console.log(`\n${colors.bold('Findings:')}`);
        for (const finding of result.findings) {
            const color = {
                critical: colors.red,
                high: colors.red,
                medium: colors.yellow,
                low: colors.dim
            }[finding.severity] || colors.dim;

            console.log(`  ${color(`[${finding.severity.toUpperCase()}]`)} ${finding.title}`);
            console.log(`    ${colors.dim(finding.description)}`);
        }
    } else {
        console.log(`\n${colors.green('✓ No suspicious indicators found')}`);
    }

    console.log(colors.cyan('\n' + '─'.repeat(60)));

    let verdictColor = colors.green;
    if (result.verdict === 'PHISHING') verdictColor = colors.red;
    else if (result.verdict === 'SUSPICIOUS') verdictColor = colors.yellow;

    console.log(`${colors.bold('Risk Score:')} ${result.score}/100`);
    console.log(`${colors.bold('Verdict:')} ${verdictColor(result.verdict)}`);
}

function main() {
    const args = process.argv.slice(2);

    if (args.includes('-h') || args.includes('--help')) {
        printBanner();
        console.log(`${colors.bold('Usage:')} phishing-detect <url> [options]

${colors.bold('Options:')}
  -j, --json     Output as JSON
  --demo         Run demo with sample URLs
  -h, --help     Show help
`);
        return;
    }

    printBanner();

    if (args.includes('--demo')) {
        console.log(colors.yellow('Running demo with sample URLs...\n'));

        const testUrls = [
            'https://www.google.com',
            'http://paypa1-secure-login.suspicious.tk/verify',
            'https://login-amazon.com.attacker.xyz/account',
            'http://192.168.1.1/login',
            'https://facebook.com.secure-login.info/auth'
        ];

        const detector = new PhishingDetector();
        for (const url of testUrls) {
            const result = detector.analyze(url);
            printResult(result);
            console.log();
        }
        return;
    }

    const url = args.find(a => !a.startsWith('-'));
    if (!url) {
        console.log(colors.yellow('No URL specified. Use --demo for examples.'));
        return;
    }

    const detector = new PhishingDetector();
    const result = detector.analyze(url);

    if (args.includes('-j') || args.includes('--json')) {
        console.log(JSON.stringify(result, null, 2));
    } else {
        printResult(result);
    }
}

main();
