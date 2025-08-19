class SafeHavenAnalysis {
    constructor() {
        this.apiUrl = window.location.pathname; // Will use current URL or set specific endpoint
        this.init();
    }

    init() {
        this.csrfToken = this.getCSRFToken();
        this.bindEvents();
    }

    getCSRFToken() {
        // Get from meta tag
        const csrfMeta = document.querySelector('meta[name="csrf-token"]');
        if (csrfMeta) {
            return csrfMeta.getAttribute('content');
        }

        // Try to get CSRF token from cookie
        const cookies = document.cookie.split(';');
        for (let cookie of cookies) {
            const [name, value] = cookie.trim().split('=');
            if (name === 'csrftoken') {
                return value;
            }
        }

        return null;
    }

    bindEvents() {
        document.getElementById('analyze-btn').addEventListener('click', () => {
            const prompt = document.getElementById('prompt-input').value.trim();
            this.performAnalysis(prompt);
        });

        document.getElementById('auto-analyze-btn').addEventListener('click', () => {
            this.performAnalysis(''); // Empty prompt for auto-analysis
        });
    }

    async performAnalysis(prompt = '') {
        const loadingDiv = document.getElementById('loading');
        const resultsContainer = document.getElementById('response-container');
        const analyzeBtn = document.getElementById('analyze-btn');
        const autoAnalyzeBtn = document.getElementById('auto-analyze-btn');

        // Show loading state
        loadingDiv.style.display = 'block';
        analyzeBtn.disabled = true;
        autoAnalyzeBtn.disabled = true;
        resultsContainer.innerHTML = '<p>Analyzing...</p>';

        try {
            const response = await fetch(this.apiUrl, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': this.csrfToken || '',
                },
                credentials: 'same-origin',
                body: JSON.stringify({
                    prompt: prompt
                })
            });

            const data = await response.json();

            if (response.ok) {
                if (data.status === 'success') {
                    this.displayResults(data.response, prompt);
                    this.addToHistory(prompt, data.response);
                    document.getElementById('prompt-input').value = '';
                } else {
                    this.displayError('Analysis completed but returned unexpected status');
                }
            } else {
                this.displayError(data.error || 'Analysis failed');
            }
        } catch (error) {
            console.error('Analysis error:', error);
            this.displayError('Network error occurred. Please try again.');
        } finally {
            loadingDiv.style.display = 'none';
            analyzeBtn.disabled = false;
            autoAnalyzeBtn.disabled = false;
        }
    }

    displayResults(response, prompt) {
        const container = document.getElementById('response-container');
        const analysisType = prompt ? 'Manual Analysis' : 'Auto-Analysis of Recent Incidents';

        container.innerHTML = `
            <div class="analysis-result">
                <h3>${analysisType}</h3>
                ${prompt ? `<p><strong>Prompt:</strong> ${this.escapeHtml(prompt)}</p>` : ''}
                <p><strong>AI Analysis:</strong></p>
                <div class="ai-response">${this.formatResponse(response)}</div>
                <p><small>Analysis completed at: ${new Date().toLocaleString()}</small></p>
            </div>
        `;
    }

    displayError(error) {
        const container = document.getElementById('response-container');
        container.innerHTML = `
            <div class="error">
                <p><strong>Error:</strong> ${this.escapeHtml(error)}</p>
                <p><small>Error occurred at: ${new Date().toLocaleString()}</small></p>
            </div>
        `;
    }

    addToHistory(prompt, response) {
        const historyContainer = document.getElementById('history-container');
        const analysisType = prompt ? 'Manual' : 'Auto';

        // If this is the first entry, clear the "No previous analyses" message
        if (historyContainer.innerHTML.includes('No previous analyses')) {
            historyContainer.innerHTML = '';
        }

        const historyItem = document.createElement('div');
        historyItem.className = 'history-item';
        historyItem.innerHTML = `
            <div class="history-entry">
                <h4>${analysisType} Analysis - ${new Date().toLocaleString()}</h4>
                ${prompt ? `<p><strong>Prompt:</strong> ${this.escapeHtml(prompt)}</p>` : ''}
                <p><strong>Response:</strong></p>
                <div class="history-response">${this.formatResponse(response)}</div>
            </div>
            <hr>
        `;

        // Add to the top of history
        historyContainer.insertBefore(historyItem, historyContainer.firstChild);
    }

    formatResponse(response) {
        // Basic formatting for the AI response
        return this.escapeHtml(response)
            .replace(/\n/g, '<br>')
            .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
            .replace(/\*(.*?)\*/g, '<em>$1</em>');
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
}

// Initialize the application when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new SafeHavenAnalysis();
});