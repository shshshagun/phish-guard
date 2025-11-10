document.addEventListener('DOMContentLoaded', () => {
            
    /**
     * ----------------------------------------------------------------
     * App Module: Main controller
     * ----------------------------------------------------------------
     */
    const App = {
        // State
        currentAnalysisLog: null,
        allThreatsFound: [],

        // DOM Elements
        els: {
            pasteBtn: document.getElementById('paste-btn'),
            uploadBtn: document.getElementById('file-upload'),
            analyzeBtn: document.getElementById('analyze-btn'),
            analyzeBtnText: document.getElementById('analyze-btn-text'),
            analyzeSpinner: document.getElementById('analyze-spinner'),
            clearBtn: document.getElementById('clear-btn'),
            exportBtn: document.getElementById('export-btn'),
            emailInput: document.getElementById('email-input'),
            resultsList: document.getElementById('results-list'),
            resultsPlaceholder: document.getElementById('results-placeholder'),
            logConsole: document.getElementById('log-console'),
            summaryCard: document.getElementById('summary-card'),
            riskScore: document.getElementById('overall-risk-score'),
            riskLabel: document.getElementById('overall-risk-label'),
            threatsCount: document.getElementById('threats-found-count'),
            highestSeverity: document.getElementById('highest-severity'),
            popupOverlay: document.getElementById('popup-overlay'),
            popupCard: document.getElementById('popup-card'),
            popupCloseBtn: document.getElementById('popup-close-btn'),
            popupCloseBtn2: document.getElementById('popup-close-btn-2'),
            popupCopyBtn: document.getElementById('popup-copy-btn'),
            popupTitle: document.getElementById('popup-title'),
            popupBadge: document.getElementById('popup-severity-badge'),
            popupDesc: document.getElementById('popup-description'),
            popupEvidence: document.getElementById('popup-evidence'),
            popupSuggest: document.getElementById('popup-suggestion'),
        },

        init() {
            App.UI.addLog('PhishGuard v1.0.0 initialized. Ready for analysis.', 'ok');
            this.addListeners();
        },

        addListeners() {
            this.els.pasteBtn.addEventListener('click', this.onPaste);
            this.els.analyzeBtn.addEventListener('click', this.onAnalyze);
            this.els.uploadBtn.addEventListener('change', this.onFileSelect);
            this.els.clearBtn.addEventListener('click', this.onClear);
            this.els.exportBtn.addEventListener('click', this.onExport);
            
            // Popup listeners
            this.els.popupOverlay.addEventListener('click', (e) => {
                if (e.target === this.els.popupOverlay) this.UI.hidePopup();
            });
            this.els.popupCloseBtn.addEventListener('click', this.UI.hidePopup);
            this.els.popupCloseBtn2.addEventListener('click', this.UI.hidePopup);
            this.els.popupCopyBtn.addEventListener('click', this.onCopyEvidence);

            // Result list delegation
            this.els.resultsList.addEventListener('click', this.onSelectThreat);
            
            // Drag and drop
            const dropZone = this.els.emailInput; // Using textarea as dropzone
            dropZone.addEventListener('dragover', (e) => {
                e.preventDefault();
                e.stopPropagation();
                dropZone.classList.add('border-accent', 'shadow-glow');
            });
            dropZone.addEventListener('dragleave', (e) => {
                e.preventDefault();
                e.stopPropagation();
                dropZone.classList.remove('border-accent', 'shadow-glow');
            });
            dropZone.addEventListener('drop', (e) => {
                e.preventDefault();
                e.stopPropagation();
                dropZone.classList.remove('border-accent', 'shadow-glow');
                if (e.dataTransfer.files && e.dataTransfer.files[0]) {
                    this.handleFile(e.dataTransfer.files[0]);
                }
            });
        },

        async onPaste() {
            try {
                const text = await navigator.clipboard.readText();
                if (text) {
                    App.els.emailInput.value = text;
                    App.UI.addLog('Email content pasted from clipboard.', 'ok');
                } else {
                    App.UI.addLog('Clipboard is empty or permission was denied.', 'warn');
                }
            } catch (err) {
                console.error('Failed to read clipboard:', err);
                App.UI.addLog('Failed to read clipboard. Check browser permissions.', 'danger');
            }
        },
        
        onFileSelect(e) {
            if (e.target.files && e.target.files[0]) {
                App.handleFile(e.target.files[0]);
            }
        },
        
        handleFile(file) {
            const reader = new FileReader();
            reader.onload = (e) => {
                App.els.emailInput.value = e.target.result;
                App.UI.addLog(`Loaded file: ${file.name}`, 'ok');
            };
            reader.onerror = () => {
                App.UI.addLog(`Failed to read file: ${file.name}`, 'danger');
            };
            reader.readAsText(file);
        },

        async onAnalyze() {
            const rawEmail = App.els.emailInput.value;
            if (!rawEmail.trim()) {
                App.UI.addLog('Input is empty. Please paste an email.', 'warn');
                return;
            }
            
            App.UI.setLoading(true);
            App.UI.clearResults();
            App.UI.addLog('Starting analysis...');
            
            // Use setTimeout to allow UI to update before blocking
            await new Promise(resolve => setTimeout(resolve, 50));

            try {
                const parsedEmail = Parser.parse(rawEmail);
                App.UI.addLog('Email headers and body parsed.');

                const analysis = Rules.analyze(parsedEmail, App.UI.addLog);
                App.UI.addLog(`Analysis complete. Found ${analysis.threats.length} potential threats.`);
                
                App.allThreatsFound = analysis.threats; // Store for popup
                App.currentAnalysisLog = Logger.createLog(rawEmail, parsedEmail, analysis);
                
                App.UI.showSummary(analysis);
                App.UI.renderThreatList(analysis.threats);
                
                App.els.exportBtn.disabled = false;

            } catch (error) {
                console.error('Analysis Error:', error);
                App.UI.addLog(`An error occurred during analysis: ${error.message}`, 'danger');
            } finally {
                App.UI.setLoading(false);
            }
        },
        
        onClear() {
            App.els.emailInput.value = '';
            App.UI.clearResults();
            App.UI.addLog('Cleared input and results.');
            App.els.exportBtn.disabled = true;
            App.currentAnalysisLog = null;
            App.allThreatsFound = [];
        },
        
        onExport() {
            if (!App.currentAnalysisLog) {
                App.UI.addLog('No analysis log to export.', 'warn');
                return;
            }
            try {
                Logger.exportLog(App.currentAnalysisLog);
                App.UI.addLog('JSON log exported successfully.', 'ok');
            } catch (error) {
                console.error('Export Error:', error);
                App.UI.addLog(`Failed to export log: ${error.message}`, 'danger');
            }
        },
        
        onSelectThreat(e) {
            const threatCard = e.target.closest('[data-threat-id]');
            if (threatCard) {
                const threatId = threatCard.dataset.threatId;
                const threat = App.allThreatsFound.find(t => t.id === threatId);
                if (threat) {
                    App.UI.showPopup(threat);
                }
            }
        },
        
        onCopyEvidence() {
            const evidenceText = App.els.popupEvidence.textContent;
            try {
                // Use execCommand as clipboard.writeText might fail in iFrames
                const textArea = document.createElement("textarea");
                textArea.value = evidenceText;
                textArea.style.position = "fixed";  // Avoid scrolling to bottom
                textArea.style.opacity = 0;
                document.body.appendChild(textArea);
                textArea.focus();
                textArea.select();
                document.execCommand('copy');
                document.body.removeChild(textArea);
                App.UI.addLog('Evidence copied to clipboard.', 'ok');
            } catch (err) {
                console.error('Failed to copy text:', err);
                App.UI.addLog('Failed to copy evidence.', 'danger');
            }
        }
    };

    /**
     * ----------------------------------------------------------------
     * App.UI Module: Handles all DOM manipulations
     * ----------------------------------------------------------------
     */
    App.UI = {
        addLog(message, level = 'info') {
            const el = App.els.logConsole;
            const entry = document.createElement('div');
            entry.classList.add('log-entry');
            
            let colorClass = 'text-muted';
            if (level === 'ok') colorClass = 'text-ok';
            if (level === 'warn') colorClass = 'text-warn';
            if (level === 'danger') colorClass = 'text-danger';
            
            const time = new Date().toLocaleTimeString();
            entry.innerHTML = `<span class="text-white/40">${time}</span> - <span class="${colorClass}">${message}</span>`;
            
            el.appendChild(entry);
            el.scrollTop = el.scrollHeight; // Auto-scroll
        },

        setLoading(isLoading) {
            if (isLoading) {
                App.els.analyzeBtn.disabled = true;
                App.els.analyzeBtnText.classList.add('hidden');
                App.els.analyzeSpinner.classList.remove('hidden');
            } else {
                App.els.analyzeBtn.disabled = false;
                App.els.analyzeBtnText.classList.remove('hidden');
                App.els.analyzeSpinner.classList.add('hidden');
            }
        },
        
        clearResults() {
            App.els.resultsList.innerHTML = '';
            App.els.resultsPlaceholder.classList.remove('hidden');
            App.els.summaryCard.classList.add('hidden');
            App.els.riskScore.textContent = '--';
            App.els.riskLabel.textContent = 'Not Scanned';
            App.els.threatsCount.textContent = '0';
            App.els.highestSeverity.textContent = 'None';
            App.els.highestSeverity.className = 'text-base font-medium capitalize px-3 py-1 rounded-full bg-gray-600 text-white mt-1';
        },
        
        showSummary(analysis) {
            const { overallScore, threats } = analysis;
            App.els.summaryCard.classList.remove('hidden');
            
            App.els.riskScore.textContent = overallScore;
            App.els.threatsCount.textContent = threats.length;

            let riskLabel = 'Low';
            let riskColor = 'text-ok';
            let riskBg = 'bg-ok/20';

            if (overallScore >= 70) {
                riskLabel = 'High';
                riskColor = 'text-danger';
                riskBg = 'bg-danger/20';
            } else if (overallScore >= 40) {
                riskLabel = 'Medium';
                riskColor = 'text-warn';
                riskBg = 'bg-warn/20';
            }
            
            App.els.riskLabel.textContent = riskLabel;
            App.els.riskScore.className = `text-3xl font-bold ${riskColor}`;
            App.els.riskLabel.className = `text-sm font-medium ${riskColor}`;
            
            // Find highest severity
            let highest = 'none';
            if (threats.some(t => t.severity === 'high')) highest = 'high';
            else if (threats.some(t => t.severity === 'medium')) highest = 'medium';
            else if (threats.some(t => t.severity === 'low')) highest = 'low';
            
            const severityClass = this.getSeverityClasses(highest, 'badge');
            App.els.highestSeverity.textContent = highest;
            App.els.highestSeverity.className = `text-base font-medium capitalize px-3 py-1 rounded-full mt-1 ${severityClass}`;
        },

        renderThreatList(threats) {
            if (threats.length === 0) {
                App.els.resultsPlaceholder.classList.remove('hidden');
                App.els.resultsPlaceholder.innerHTML = `
                    <svg xmlns="http://www.w3.org/2000/svg" class="h-16 w-16 opacity-30 text-ok" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1">
                      <path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                    </svg>
                    <p class="mt-4 text-lg text-white">No Threats Found</p>
                    <p class="text-sm">This email appears to be safe.</p>`;
                return;
            }

            App.els.resultsPlaceholder.classList.add('hidden');
            App.els.resultsList.innerHTML = '';
            
            const severityScore = { 'high': 3, 'medium': 2, 'low': 1, 'info': 0 };
            threats.sort((a, b) => severityScore[b.severity] - severityScore[a.severity]);

            threats.forEach(threat => {
                const item = this.createThreatElement(threat);
                App.els.resultsList.appendChild(item);
            });
        },
        
        createThreatElement(threat) {
            const el = document.createElement('div');
            el.className = 'glass p-3 rounded-lg flex items-center justify-between cursor-pointer hover:border-accent transition-all animate-fade-in';
            el.dataset.threatId = threat.id;

            const { icon, colorClass } = this.getSeverityClasses(threat.severity, 'icon');
            
            el.innerHTML = `
                <div class="flex items-center gap-3 overflow-hidden">
                    <span class="flex-shrink-0 h-8 w-8 rounded-full ${colorClass} text-white flex items-center justify-center">
                        ${icon}
                    </span>
                    <div class="overflow-hidden">
                        <h3 class="font-semibold text-white truncate">${threat.label}</h3>
                        <p class="text-sm text-muted truncate">${threat.description}</p>
                    </div>
                </div>
                <span class="flex-shrink-0 text-xs font-medium uppercase px-2 py-0.5 ${colorClass} text-white rounded-full ml-2">${threat.severity}</span>
            `;
            return el;
        },
        
        getSeverityClasses(severity, type) {
            const icons = {
                high: `<svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" /></svg>`,
                medium: `<svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>`,
                low: `<svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m6 0a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>`,
                none: `<svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M5 13l4 4L19 7" /></svg>`
            };
            const colors = {
                high: 'bg-danger',
                medium: 'bg-warn',
                low: 'bg-ok',
                none: 'bg-gray-600'
            };
            
            if(type === 'badge') return colors[severity] || colors.none;
            
            return {
                icon: icons[severity] || icons.none,
                colorClass: colors[severity] || colors.none
            };
        },
        
        showPopup(threat) {
            App.els.popupTitle.textContent = threat.label;
            App.els.popupDesc.textContent = threat.description;
            App.els.popupEvidence.textContent = threat.evidence;
            App.els.popupSuggest.textContent = threat.suggestion;
            
            const badgeClass = this.getSeverityClasses(threat.severity, 'badge');
            App.els.popupBadge.textContent = threat.severity;
            App.els.popupBadge.className = `text-xs font-medium uppercase px-3 py-1 rounded-full text-white ${badgeClass}`;
            
            App.els.popupOverlay.classList.remove('hidden');
            // Focus the close button for accessibility
            App.els.popupCloseBtn.focus();
        },
        
        hidePopup() {
            App.els.popupOverlay.classList.add('hidden');
            App.els.analyzeBtn.focus(); // Return focus
        }
    };
    
    /**
     * ----------------------------------------------------------------
     * Parser Module: Handles email text parsing
     * ----------------------------------------------------------------
     */
    const Parser = {
        parse(rawEmail) {
            const separator = rawEmail.search(/\r?\n\r?\n/);
            const headerString = (separator === -1) ? rawEmail : rawEmail.substring(0, separator);
            const body = (separator === -1) ? '' : rawEmail.substring(separator + 2).trim();
            
            const headers = this.parseHeaders(headerString);
            const urls = this.extractUrls(body);
            const attachments = this.extractAttachments(body, headers);
            const htmlBody = this.extractHtmlBody(body);
            
            return { rawEmail, headers, body, urls, attachments, htmlBody };
        },
        
        parseHeaders(headerString) {
            const headers = {};
            let currentHeader = '';
            const lines = headerString.split(/\r?\n/);

            lines.forEach(line => {
                if (line.startsWith(' ') || line.startsWith('\t')) {
                    // Folded header
                    if (currentHeader) {
                        headers[currentHeader] = (headers[currentHeader] || '') + ' ' + line.trim();
                    }
                } else {
                    const separatorIndex = line.indexOf(':');
                    if (separatorIndex > 0) {
                        const key = line.substring(0, separatorIndex).trim().toLowerCase();
                        const value = line.substring(separatorIndex + 1).trim();
                        currentHeader = key;
                        
                        // Store headers that can appear multiple times (like Received) as arrays
                        if (['received', 'authentication-results'].includes(key)) {
                            if (!headers[key]) headers[key] = [];
                            headers[key].push(value);
                        } else {
                            headers[key] = value;
                        }
                    }
                }
            });
            return headers;
        },
        
        extractUrls(text) {
            // Regex to find URLs. Fairly comprehensive.
            const urlRegex = /(?:(?:https?|ftp):\/\/|www\.|ftp\.)(?:\([-A-Z0-9+&@#\/%=~_|$?!:,.]*\)|[-A-Z0-9+&@#\/%=~_|$?!:,.])*(?:\([-A-Z0-9+&@#\/%=~_|$?!:,.]*\)|[A-Z0-9+&@#\/%=~_|$])/igm;
            const matches = text.match(urlRegex) || [];
            // Decode HTML entities like &amp;
            return matches.map(url => url.replace(/&amp;/g, '&'));
        },
        
        extractAttachments(body, headers) {
            const attachmentRegex = /filename="?([^"]+)"?/gi;
            const contentDisp = headers['content-disposition'] || '';
            let matches = [...contentDisp.matchAll(attachmentRegex)];
            
            // Also check body for filename patterns
            matches = matches.concat([...body.matchAll(attachmentRegex)]);
            
            return matches.map(match => match[1]); // Return just the filenames
        },
        
        extractHtmlBody(body) {
            // Basic check for HTML content
            if (/Content-Type: text\/html/i.test(body) || /<html/i.test(body)) {
                // Try to find the HTML part. This is a simplification.
                const htmlMatch = body.match(/<html[\s\S]*<\/html>/i);
                if(htmlMatch) return htmlMatch[0];
            }
            // If no HTML, or if it's plain text, return the whole body for link parsing
            return body;
        }
    };

    /**
     * ----------------------------------------------------------------
     * Rules Module: The core analysis engine
     * ----------------------------------------------------------------
     */
    const Rules = {
        // List of rules from the JSON spec
        DEFINITIONS: [
            {
                id: 'dkim-spf-fail',
                label: 'SPF/DKIM/DMARC Fail',
                description: 'Email authentication (SPF, DKIM, DMARC) checks failed or are missing, suggesting the sender may be forged.',
                suggestion: 'Do not trust this sender. Check the headers for "Authentication-Results". A "fail" or "softfail" is a major red flag.',
                severity: 'high',
                check: (parsed, log) => {
                    const authResults = [].concat(parsed.headers['authentication-results'] || []).join(' ');
                    if (!authResults) {
                        log('No Authentication-Results header found. This is common, but not ideal.', 'info');
                        return false;
                    }
                    
                    const spfFail = /spf=(fail|softfail)/i.test(authResults);
                    const dkimFail = /dkim=(fail|none)/i.test(authResults);
                    const dmarcFail = /dmarc=(fail|reject)/i.test(authResults);
                    
                    let evidence = [];
                    if (spfFail) evidence.push('SPF check failed.');
                    if (dkimFail) evidence.push('DKIM signature failed or was missing.');
                    if (dmarcFail) evidence.push('DMARC policy failed.');
                    
                    if (evidence.length > 0) {
                        return { triggered: true, evidence: evidence.join('\n') + `\n\nFull Header: ${authResults.substring(0, 200)}...` };
                    }
                    return false;
                }
            },
            {
                id: 'replyto-mismatch',
                label: 'Reply-To Mismatch',
                description: 'The "Reply-To" address is different from the "From" address, a common tactic to redirect replies to an attacker.',
                suggestion: 'Be cautious. Verify if the "Reply-To" address is legitimate before replying. Attackers set this to capture your response.',
                severity: 'medium',
                check: (parsed) => {
                    const from = parsed.headers['from'];
                    const replyTo = parsed.headers['reply-to'];
                    
                    if (from && replyTo && from !== replyTo) {
                        const fromDomain = Rules.Helpers.extractDomain(Rules.Helpers.extractEmail(from));
                        const replyToDomain = Rules.Helpers.extractDomain(Rules.Helpers.extractEmail(replyTo));
                        
                        if(fromDomain && replyToDomain && fromDomain !== replyToDomain) {
                            return { triggered: true, evidence: `From: ${from}\nReply-To: ${replyTo}` };
                        }
                    }
                    return false;
                }
            },
            {
                id: 'suspicious-from',
                label: 'Suspicious From Address',
                description: 'The "From" address uses a display name to impersonate a person or brand, while the actual email address is unrelated.',
                suggestion: 'Always check the full email address, not just the display name. Hover over the sender name to reveal the real address.',
                severity: 'high',
                check: (parsed) => {
                    const from = parsed.headers['from'];
                    if (!from) return false;
                    
                    const email = Rules.Helpers.extractEmail(from);
                    const name = from.replace(`<${email}>`, '').replace(/"/g, '').trim();
                    
                    if (name.toLowerCase() !== email.split('@')[0].toLowerCase()) {
                        // Check if name contains a "brand" and email domain is different
                        const nameDomain = Rules.Helpers.extractDomain(name.replace(/\s/g, '')); // e.g. "Support @ PayPal"
                        const emailDomain = Rules.Helpers.extractDomain(email);
                        if (nameDomain && emailDomain && nameDomain !== emailDomain) {
                             return { triggered: true, evidence: `Display Name: "${name}"\nActual Email: <${email}>\n\nDisplay name domain (${nameDomain}) does not match email domain (${emailDomain}).` };
                        }
                    }
                    return false;
                }
            },
            {
                id: 'mismatched-links',
                label: 'Displayed vs. Actual Link Mismatch',
                description: 'A link in the email body displays one website (e.g., "yourbank.com") but actually links to a different, malicious site.',
                suggestion: 'Always hover your mouse over links before clicking to see the *actual* destination URL in your browser\'s corner.',
                severity: 'high',
                check: (parsed) => {
                    const htmlBody = parsed.htmlBody;
                    if (!htmlBody) return false;
                    
                    try {
                        const doc = new DOMParser().parseFromString(htmlBody, 'text/html');
                        const links = doc.querySelectorAll('a[href]');
                        let mismatches = [];
                        
                        links.forEach(a => {
                            const href = a.getAttribute('href');
                            const text = a.textContent.trim();
                            
                            if (href && text && !href.startsWith('mailto:') && !href.startsWith('#')) {
                                const hrefDomain = Rules.Helpers.extractDomain(href);
                                const textDomain = Rules.Helpers.extractDomain(text);
                                
                                if (hrefDomain && textDomain && hrefDomain !== textDomain) {
                                    mismatches.push(`Displayed: "${text}"\nActual Link: "${href}"`);
                                }
                            }
                        });
                        
                        if (mismatches.length > 0) {
                            return { triggered: true, evidence: mismatches.join('\n\n') };
                        }
                    } catch (e) {
                        console.error('HTML parsing error:', e);
                    }
                    return false;
                }
            },
            {
                id: 'url-typo-squatting',
                label: 'URL Typosquatting / IDN Homograph',
                description: 'URLs contain suspicious characters (Punycode "xn--") or common typos (e.g., "paypa1.com") to trick you.',
                suggestion: 'Look closely at all links. Punycode (starting with "xn--") can hide foreign characters that look like English letters.',
                severity: 'high',
                check: (parsed) => {
                    const punycodeRegex = /xn--/i;
                    const suspiciousUrls = parsed.urls.filter(url => punycodeRegex.test(url));
                    
                    if (suspiciousUrls.length > 0) {
                        return { triggered: true, evidence: `Found Punycode URLs (IDN Homograph attack):\n${suspiciousUrls.join('\n')}` };
                    }
                    return false;
                }
            },
            {
                id: 'url-shortener',
                label: 'Obfuscated Shortener',
                description: 'Uses a URL shortener (like bit.ly) to hide the final, potentially malicious, destination of a link.',
                suggestion: 'Be extremely cautious with shortened links. Use a link-expander tool to check the destination *before* clicking.',
                severity: 'medium',
                check: (parsed) => {
                    const shortenerRegex = /(bit\.ly|t\.co|tinyurl\.com|is\.gd|goo\.gl|buff\.ly)/i;
                    const shorteners = parsed.urls.filter(url => shortenerRegex.test(url));
                    
                    if (shorteners.length > 0) {
                        return { triggered: true, evidence: `Found shortened URLs:\n${shorteners.join('\n')}` };
                    }
                    return false;
                }
            },
            {
                id: 'urgent-language',
                label: 'Urgent / Fear Language',
                description: 'Uses words like "urgent," "immediately," or "account locked" to create panic and rush you into making a mistake.',
                suggestion: 'Attackers use urgency to prevent you from thinking. Legitimate companies rarely demand immediate, urgent action via email.',
                severity: 'medium',
                check: (parsed) => {
                    const urgencyRegex = /(urgent|immediately|verify now|account locked|action required|suspension|security alert|warning|confirm your account)/gi;
                    const matches = parsed.body.match(urgencyRegex);
                    
                    if (matches && matches.length > 2) { // Require a few matches
                        return { triggered: true, evidence: `Found ${matches.length} urgent phrases:\n"${[...new Set(matches)].join('", "')}"` };
                    }
                    return false;
                }
            },
            {
                id: 'generic-greeting',
                label: 'Generic Greeting',
                description: 'Uses a generic greeting like "Dear Customer" or "Valued User" instead of your actual name.',
                suggestion: 'Your bank or services you use (like Netflix, Amazon) will almost always address you by your real name.',
                severity: 'low',
                check: (parsed) => {
                    const genericRegex = /Dear (Customer|User|Valued Member|Client|Account Holder|Subscriber)/i;
                    const match = parsed.body.match(genericRegex);
                    
                    if (match) {
                        return { triggered: true, evidence: `Found generic greeting: "${match[0]}"` };
                    }
                    return false;
                }
            },
            {
                id: 'suspicious-attachment',
                label: 'Suspicious Attachment',
                description: 'Contains attachments with dangerous file extensions like ".exe", ".zip", ".js", or ".html" often used to deliver malware.',
                suggestion: 'NEVER open attachments you were not expecting. Be especially wary of .zip, .html, .js, .exe, or .scr files.',
                severity: 'high',
                check: (parsed) => {
                    const suspiciousExt = /\.(exe|scr|bat|com|vbs|js|html|htm|zip|rar|7z|pdf\.exe|docm|xlsm)$/i;
                    const suspiciousFiles = parsed.attachments.filter(file => suspiciousExt.test(file));
                    
                    if (suspiciousFiles.length > 0) {
                        return { triggered: true, evidence: `Found suspicious attachments:\n${suspiciousFiles.join('\n')}` };
                    }
                    return false;
                }
            },
        ],
        
        analyze(parsedEmail, log) {
            log('Analyzing email with ' + this.DEFINITIONS.length + ' rules...');
            let threats = [];
            let overallScore = 0;
            const severityWeight = { 'high': 30, 'medium': 15, 'low': 5 };

            this.DEFINITIONS.forEach(rule => {
                try {
                    const result = rule.check(parsedEmail, log);
                    if (result && result.triggered) {
                        threats.push({
                            id: rule.id,
                            label: rule.label,
                            description: rule.description,
                            suggestion: rule.suggestion,
                            severity: rule.severity,
                            evidence: result.evidence || 'N/A'
                        });
                        overallScore += severityWeight[rule.severity] || 0;
                    }
                } catch (e) {
                    console.error(`Error in rule ${rule.id}:`, e);
                    log(`Error running rule "${rule.id}"`, 'danger');
                }
            });
            
            overallScore = Math.min(100, overallScore); // Cap at 100
            log(`Calculated score: ${overallScore}`);
            
            return { threats, overallScore };
        },
        
        // Helper functions
        Helpers: {
            extractEmail(text) {
                const match = text.match(/<([^>]+)>/);
                return match ? match[1] : text.trim();
            },
            extractDomain(text) {
                if (!text) return null;
                try {
                    // Try parsing as URL first
                    let url = text;
                    if (!url.startsWith('http') && url.includes('@')) {
                        url = 'http://' + url.split('@')[1]; // from email
                    } else if (!url.startsWith('http')) {
                        url = 'http://' + url;
                    }
                    
                    let domain = new URL(url).hostname;
                    domain = domain.replace(/^www\./, ''); // remove www
                    return domain;
                } catch (e) {
                    // Not a valid URL, maybe just a domain string?
                    const domainMatch = text.match(/([a-z0-9\-]+\.)+[a-z]{2,}/i);
                    if(domainMatch) {
                        let domain = domainMatch[0].replace(/^www\./, '');
                        return domain;
                    }
                    return null;
                }
            }
        }
    };

    /**
     * ----------------------------------------------------------------
     * Logger Module: Handles JSON log creation and export
     * ----------------------------------------------------------------
     */
    const Logger = {
        createLog(rawEmail, parsed, analysis) {
            // Simple hash function (NOT for crypto, just for ID)
            const simpleHash = (s) => {
                let hash = 0;
                for (let i = 0; i < s.length; i++) {
                    const char = s.charCodeAt(i);
                    hash = ((hash << 5) - hash) + char;
                    hash = hash & hash; // Convert to 32bit integer
                }
                return 'sha256-sim-' + Math.abs(hash);
            }
            
            const logData = {
                timestamp: new Date().toISOString(),
                input_type: 'paste', // TODO: Differentiate
                input_hash: simpleHash(rawEmail),
                parsed_headers: {
                    from: parsed.headers['from'],
                    to: parsed.headers['to'],
                    subject: parsed.headers['subject'],
                    'reply-to': parsed.headers['reply-to'],
                    'authentication-results': parsed.headers['authentication-results'] || 'N/A'
                },
                detected_urls: parsed.urls,
                detected_attachments: parsed.attachments,
                rules_triggered: analysis.threats.map(t => ({
                    rule_id: t.id,
                    severity: t.severity,
                    evidence_snippet: t.evidence.substring(0, 150) + '...'
                })),
                overall_score: analysis.overallScore,
                user_actions: [], // Not implemented in this version
                client_info: navigator.userAgent,
                version: 'v1.0.0'
            };
            return logData;
        },
        
        exportLog(logData) {
            const jsonString = JSON.stringify(logData, null, 2);
            const blob = new Blob([jsonString], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            
            const a = document.createElement('a');
            a.href = url;
            a.download = `PhishGuard_Log_${logData.timestamp}.json`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        }
    };

    // Initialize the application
    App.init();
    
});
