// Application Data
const appData = {
  "categories": {
    "1": "Footholds",
    "2": "Files Containing Usernames", 
    "3": "Files Containing Passwords",
    "4": "Files Containing Juicy Info",
    "5": "Sensitive Directories",
    "6": "Web Server Detection",
    "7": "Vulnerable Files",
    "8": "Vulnerable Servers", 
    "9": "Error Messages",
    "10": "Sensitive Online Shopping Info",
    "11": "Network or Vulnerability Data",
    "12": "Pages Containing Login Portals",
    "13": "Various Online Devices",
    "14": "Advisories and Vulnerabilities"
  },
  "dorks_by_category": {
    "1": [
      "site:{target} intitle:\"Apache Status\" \"Apache Server Status for\"",
      "site:{target} intitle:\"Index of /admin\"",
      "site:{target} intitle:\"Welcome to nginx!\"",
      "site:{target} intitle:\"Test Page for the Apache HTTP Server\"",
      "site:{target} intitle:\"Default Web Site Page\"",
      "site:{target} inurl:\"server-status\"",
      "site:{target} inurl:\"/admin/\" intitle:\"admin\"",
      "site:{target} intitle:\"IIS Windows Server\"",
      "site:{target} intitle:\"Apache2 Ubuntu Default Page\"",
      "site:{target} intitle:\"Index of /\" \"Parent Directory\""
    ],
    "2": [
      "site:{target} filetype:txt username password",
      "site:{target} \"username.xlsx\" ext:xlsx",
      "site:{target} intext:\"mysql_connect\" filetype:php",
      "site:{target} filetype:sql \"INSERT INTO users\"",
      "site:{target} filetype:csv username",
      "site:{target} intitle:\"index of\" \"user.txt\"",
      "site:{target} filetype:log username",
      "site:{target} \"username=\" ext:txt",
      "site:{target} intitle:\"index of\" \"users.sql\"",
      "site:{target} filetype:xls username"
    ],
    "3": [
      "site:{target} filetype:env \"DB_PASSWORD\"",
      "site:{target} \"admin password\" filetype:txt",
      "site:{target} intitle:\"index of\" \"passwords.txt\"",
      "site:{target} filetype:sql password",
      "site:{target} \"password=\" ext:txt",
      "site:{target} intitle:\"index of\" \"password.txt\"",
      "site:{target} filetype:cfg password",
      "site:{target} \"root password\" filetype:txt",
      "site:{target} intitle:\"index of\" \"admin.txt\"",
      "site:{target} filetype:ini password"
    ],
    "4": [
      "site:{target} filetype:pdf \"confidential\"",
      "site:{target} intext:\"/login.php\" intitle:\"login\"",
      "site:{target} filetype:xls \"social security number\"",
      "site:{target} filetype:doc \"confidential\"",
      "site:{target} \"strictly confidential\" filetype:pdf",
      "site:{target} filetype:xlsx \"personal information\"",
      "site:{target} \"internal use only\" filetype:doc",
      "site:{target} filetype:ppt \"confidential\"",
      "site:{target} \"do not distribute\" filetype:pdf",
      "site:{target} filetype:txt \"classified\""
    ],
    "5": [
      "site:{target} intitle:\"index of\" /backup",
      "site:{target} intitle:\"index of\" /config",
      "site:{target} intitle:\"index of\" /private",
      "site:{target} intitle:\"index of\" /temp",
      "site:{target} intitle:\"index of\" /logs",
      "site:{target} intitle:\"index of\" /admin",
      "site:{target} intitle:\"index of\" /db",
      "site:{target} intitle:\"index of\" /files",
      "site:{target} intitle:\"index of\" /upload",
      "site:{target} intitle:\"index of\" /downloads"
    ],
    "6": [
      "site:{target} intitle:\"Apache2 Debian Default Page\"",
      "site:{target} \"Server: Microsoft-IIS\" filetype:txt",
      "site:{target} intitle:\"IIS Windows Server\"",
      "site:{target} \"nginx/\" \"server\"",
      "site:{target} \"Apache/\" \"server\"",
      "site:{target} intitle:\"Welcome to nginx!\"",
      "site:{target} \"lighttpd\" \"server\"",
      "site:{target} intitle:\"Test Page for Apache\"",
      "site:{target} \"Server: nginx\"",
      "site:{target} \"powered by Apache\""
    ],
    "7": [
      "site:{target} filetype:php inurl:\"config.php\"",
      "site:{target} filetype:sql \"INSERT INTO users\"",
      "site:{target} \"wp-config.php\" filetype:txt",
      "site:{target} filetype:conf",
      "site:{target} filetype:ini",
      "site:{target} filetype:cnf",
      "site:{target} filetype:cfg",
      "site:{target} \"database.yml\" filetype:yml",
      "site:{target} \".env\" filetype:env",
      "site:{target} \"settings.php\" filetype:php"
    ],
    "8": [
      "site:{target} inurl:\"/phpMyAdmin/\" intitle:\"Welcome to phpMyAdmin\"",
      "site:{target} intitle:\"MantisBT\" \"Administration\"",
      "site:{target} inurl:\"/admin\" intitle:\"admin panel\"",
      "site:{target} intitle:\"Tomcat\" \"Server Administration\"",
      "site:{target} intitle:\"Webmin\" login",
      "site:{target} intitle:\"cPanel\" login",
      "site:{target} intitle:\"WHM\" \"Web Host Manager\"",
      "site:{target} intitle:\"Plesk\" login",
      "site:{target} intitle:\"DirectAdmin\" login",
      "site:{target} inurl:\"/manager/html\" intitle:\"Tomcat\""
    ],
    "9": [
      "site:{target} \"Error Diagnostic Information\" intitle:\"Error Occurred While\"",
      "site:{target} \"MySQL Error\" \"Warning: mysql_connect()\"",
      "site:{target} \"dispatch = debugger.\"",
      "site:{target} \"Warning: mysql_connect()\"",
      "site:{target} \"Error: ORA-\"",
      "site:{target} \"Microsoft OLE DB Provider for ODBC Drivers error\"",
      "site:{target} \"Error Occurred While Processing Request\"",
      "site:{target} \"Warning: Division by zero\"",
      "site:{target} \"PHP Warning:\"",
      "site:{target} \"SQL syntax error\""
    ],
    "10": [
      "site:{target} filetype:xls \"credit card number\"",
      "site:{target} \"payment\" filetype:csv \"card\"",
      "site:{target} \"visa\" \"mastercard\" filetype:txt",
      "site:{target} \"credit card\" \"expir\" filetype:xls",
      "site:{target} \"payment info\" filetype:doc",
      "site:{target} \"billing address\" filetype:csv"
    ],
    "11": [
      "site:{target} filetype:log \"failed password for root\"",
      "site:{target} intitle:\"VNC viewer for Java\"",
      "site:{target} filetype:log \"authentication failure\"",
      "site:{target} \"VNC Desktop\" intitle:",
      "site:{target} filetype:pcap",
      "site:{target} intitle:\"Network Query Tool\""
    ],
    "12": [
      "site:{target} intitle:\"Login\" inurl:\"/admin\"",
      "site:{target} \"please login\" \"username\" \"password\"",
      "site:{target} intitle:\"User Login\"",
      "site:{target} inurl:\"login.php\"",
      "site:{target} intitle:\"Admin Login\"",
      "site:{target} inurl:\"/wp-login.php\""
    ],
    "13": [
      "site:{target} intext:\"Camera Live Image\"",
      "site:{target} intitle:\"DVR\" \"Network Camera\"",
      "site:{target} intitle:\"Network Camera\"",
      "site:{target} intitle:\"Live View\" \"Axis\"",
      "site:{target} intitle:\"Web Camera\"",
      "site:{target} intitle:\"TOSHIBA Network Camera\""
    ],
    "14": [
      "site:{target} \"SQL injection vulnerability\" filetype:txt",
      "site:{target} \"XSS vulnerability\" site:cve.mitre.org",
      "site:{target} \"security advisory\"",
      "site:{target} \"vulnerability report\"",
      "site:{target} \"CVE-\" filetype:txt",
      "site:{target} \"security bulletin\""
    ]
  },
  "operators": {
    "site:": "Restricts search to a specific domain",
    "filetype:": "Searches for specific file types", 
    "intitle:": "Searches for terms in the page title",
    "inurl:": "Searches for terms in the URL",
    "intext:": "Searches for terms in the page content",
    "ext:": "Similar to filetype, searches for file extensions",
    "cache:": "Shows cached version of a page",
    "related:": "Finds pages related to a given URL",
    "allintext:": "All terms must appear in the text",
    "allintitle:": "All terms must appear in the title",
    "allinurl:": "All terms must appear in the URL"
  },
  "ethical_guidelines": [
    "Only use Google dorking for authorized security testing and research",
    "Respect robots.txt and terms of service",
    "Do not access or download sensitive information without permission", 
    "Report discovered vulnerabilities responsibly",
    "Use rate limiting to avoid being blocked by search engines",
    "Consider legal implications in your jurisdiction",
    "Obtain proper authorization before testing third-party systems"
  ],
  "risk_mappings": {
    "1": "Medium", "2": "High", "3": "Critical", "4": "Medium",
    "5": "High", "6": "Low", "7": "High", "8": "Critical",
    "9": "Medium", "10": "Critical", "11": "High", "12": "Medium",
    "13": "High", "14": "Medium"
  }
};

// Global state
let isScanning = false;
let scanResults = [];
let currentScan = null;
let selectedCategories = new Set();
let currentResult = null;

// Initialize application
document.addEventListener('DOMContentLoaded', function() {
    initializeApp();
});

function initializeApp() {
    setupEventListeners();
    renderCategories();
    renderOperators();
    renderEthicsGuidelines();
    renderCategoryCheckboxes();
    populateResultsFilters();
    
    // Initialize with all categories selected
    selectAllCategories();
    
    console.log('App initialized successfully');
}

function setupEventListeners() {
    // Tab navigation - Fixed implementation
    document.querySelectorAll('.nav-tab').forEach(tab => {
        tab.addEventListener('click', (e) => {
            e.preventDefault();
            const tabName = tab.getAttribute('data-tab');
            console.log('Switching to tab:', tabName);
            switchTab(tabName);
        });
    });
    
    // Scanner controls
    const startBtn = document.getElementById('start-scan');
    const stopBtn = document.getElementById('stop-scan');
    
    if (startBtn) startBtn.addEventListener('click', startScan);
    if (stopBtn) stopBtn.addEventListener('click', stopScan);
    
    // Category selection controls
    const selectAllBtn = document.getElementById('select-all-categories');
    const selectHighRiskBtn = document.getElementById('select-high-risk');
    const clearSelectionBtn = document.getElementById('clear-selection');
    
    if (selectAllBtn) selectAllBtn.addEventListener('click', selectAllCategories);
    if (selectHighRiskBtn) selectHighRiskBtn.addEventListener('click', selectHighRiskCategories);
    if (clearSelectionBtn) clearSelectionBtn.addEventListener('click', clearCategorySelection);
    
    // Results controls
    const exportBtn = document.getElementById('export-results');
    const clearBtn = document.getElementById('clear-results');
    
    if (exportBtn) exportBtn.addEventListener('click', exportResults);
    if (clearBtn) clearBtn.addEventListener('click', clearResults);
    
    // Results filtering
    const resultsSearch = document.getElementById('results-search');
    const categoryFilter = document.getElementById('results-category-filter');
    const riskFilter = document.getElementById('results-risk-filter');
    
    if (resultsSearch) resultsSearch.addEventListener('input', filterResults);
    if (categoryFilter) categoryFilter.addEventListener('change', filterResults);
    if (riskFilter) riskFilter.addEventListener('change', filterResults);
    
    // Modal handlers
    const modalClose = document.getElementById('modal-close');
    const modal = document.getElementById('result-modal');
    
    if (modalClose) modalClose.addEventListener('click', closeModal);
    if (modal) {
        modal.addEventListener('click', (e) => {
            if (e.target.id === 'result-modal') closeModal();
        });
    }
    
    // Modal action buttons
    const visitBtn = document.getElementById('visit-result');
    const copyBtn = document.getElementById('copy-url');
    
    if (visitBtn) visitBtn.addEventListener('click', visitResult);
    if (copyBtn) copyBtn.addEventListener('click', copyUrl);
    
    // Keyboard shortcuts
    document.addEventListener('keydown', handleKeyboardShortcuts);
}

function switchTab(tabName) {
    console.log('switchTab called with:', tabName);
    
    // Update nav tabs
    document.querySelectorAll('.nav-tab').forEach(tab => {
        tab.classList.remove('active');
        if (tab.getAttribute('data-tab') === tabName) {
            tab.classList.add('active');
        }
    });
    
    // Update tab content
    document.querySelectorAll('.tab-content').forEach(content => {
        content.classList.remove('active');
        if (content.getAttribute('data-content') === tabName) {
            content.classList.add('active');
        }
    });
    
    console.log('Tab switched to:', tabName);
}

function renderCategories() {
    const grid = document.getElementById('categories-grid');
    if (!grid) return;
    
    grid.innerHTML = '';
    
    Object.entries(appData.categories).forEach(([categoryId, categoryName]) => {
        const dorks = appData.dorks_by_category[categoryId] || [];
        const risk = appData.risk_mappings[categoryId] || 'Low';
        
        const card = document.createElement('div');
        card.className = 'category-card';
        
        card.innerHTML = `
            <div class="category-header">
                <div class="category-number">${categoryId}</div>
                <div class="category-risk risk-${risk.toLowerCase()}">${risk} Risk</div>
            </div>
            <h3 class="category-name">${categoryName}</h3>
            <p class="category-description">${getCategoryDescription(categoryId)}</p>
            <div class="category-count">${dorks.length} dorks</div>
        `;
        
        grid.appendChild(card);
    });
}

function getCategoryDescription(categoryId) {
    const descriptions = {
        '1': 'Initial access points and reconnaissance opportunities',
        '2': 'Files and documents containing username information',
        '3': 'Exposed files with password data and credentials',
        '4': 'Documents with sensitive business information',
        '5': 'Hidden directories with restricted access',
        '6': 'Information about web server configurations',
        '7': 'Files with potential security vulnerabilities',
        '8': 'Server applications with security issues',
        '9': 'System error messages revealing information',
        '10': 'E-commerce and payment-related data',
        '11': 'Network configurations and vulnerability data',
        '12': 'Authentication portals and login interfaces',
        '13': 'Internet-connected devices and systems',
        '14': 'Security advisories and vulnerability reports'
    };
    return descriptions[categoryId] || 'Security-related Google dorks';
}

function renderOperators() {
    const grid = document.getElementById('operators-grid');
    if (!grid) return;
    
    grid.innerHTML = '';
    
    Object.entries(appData.operators).forEach(([operator, description]) => {
        const card = document.createElement('div');
        card.className = 'operator-card';
        card.innerHTML = `
            <div class="operator-syntax">${operator}</div>
            <div class="operator-description">${description}</div>
        `;
        grid.appendChild(card);
    });
}

function renderEthicsGuidelines() {
    const list = document.getElementById('ethics-list');
    if (!list) return;
    
    list.innerHTML = '';
    
    appData.ethical_guidelines.forEach(guideline => {
        const item = document.createElement('li');
        item.textContent = guideline;
        list.appendChild(item);
    });
}

function renderCategoryCheckboxes() {
    const container = document.getElementById('category-checkboxes');
    if (!container) return;
    
    container.innerHTML = '';
    
    Object.entries(appData.categories).forEach(([categoryId, categoryName]) => {
        const dorks = appData.dorks_by_category[categoryId] || [];
        const risk = appData.risk_mappings[categoryId] || 'Low';
        
        const checkbox = document.createElement('div');
        checkbox.className = 'category-checkbox';
        
        checkbox.innerHTML = `
            <input type="checkbox" id="category-${categoryId}" data-category="${categoryId}" checked>
            <div class="category-checkbox-info">
                <div class="category-checkbox-name">${categoryId}. ${categoryName}</div>
                <div class="category-checkbox-count">${dorks.length} dorks</div>
            </div>
            <div class="category-checkbox-risk risk-${risk.toLowerCase()}">${risk}</div>
        `;
        
        const input = checkbox.querySelector('input');
        input.addEventListener('change', (e) => {
            if (e.target.checked) {
                selectedCategories.add(categoryId);
            } else {
                selectedCategories.delete(categoryId);
            }
        });
        
        container.appendChild(checkbox);
    });
}

function selectAllCategories() {
    selectedCategories.clear();
    document.querySelectorAll('#category-checkboxes input[type="checkbox"]').forEach(checkbox => {
        checkbox.checked = true;
        selectedCategories.add(checkbox.dataset.category);
    });
    showToast('All categories selected');
}

function selectHighRiskCategories() {
    selectedCategories.clear();
    document.querySelectorAll('#category-checkboxes input[type="checkbox"]').forEach(checkbox => {
        const categoryId = checkbox.dataset.category;
        const risk = appData.risk_mappings[categoryId];
        const isHighRisk = risk === 'High' || risk === 'Critical';
        
        checkbox.checked = isHighRisk;
        if (isHighRisk) {
            selectedCategories.add(categoryId);
        }
    });
    showToast('High risk categories selected');
}

function clearCategorySelection() {
    selectedCategories.clear();
    document.querySelectorAll('#category-checkboxes input[type="checkbox"]').forEach(checkbox => {
        checkbox.checked = false;
    });
    showToast('All categories cleared');
}

function populateResultsFilters() {
    const categoryFilter = document.getElementById('results-category-filter');
    if (!categoryFilter) return;
    
    Object.entries(appData.categories).forEach(([id, name]) => {
        const option = document.createElement('option');
        option.value = id;
        option.textContent = `${id}. ${name}`;
        categoryFilter.appendChild(option);
    });
}

async function startScan() {
    const targetInput = document.getElementById('target-input');
    const target = targetInput.value.trim();
    
    if (!target) {
        showToast('Please enter a target domain');
        return;
    }
    
    if (!isValidDomain(target)) {
        showToast('Please enter a valid domain name');
        return;
    }
    
    if (selectedCategories.size === 0) {
        showToast('Please select at least one category to scan');
        return;
    }
    
    // Start scanning
    isScanning = true;
    scanResults = []; // Clear previous results
    updateScanUI(true);
    showProgressSection(true);
    
    const includeSubdomains = document.getElementById('include-subdomains').checked;
    const delay = parseInt(document.getElementById('delay-setting').value) * 1000;
    
    try {
        await executeDoringScan(target, includeSubdomains, delay);
    } catch (error) {
        console.error('Scan error:', error);
        showToast('Scan encountered an error');
    } finally {
        isScanning = false;
        updateScanUI(false);
    }
}

function isValidDomain(domain) {
    const domainRegex = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
    return domainRegex.test(domain);
}

function updateScanUI(scanning) {
    const startBtn = document.getElementById('start-scan');
    const stopBtn = document.getElementById('stop-scan');
    
    if (startBtn && stopBtn) {
        if (scanning) {
            startBtn.classList.add('hidden');
            stopBtn.classList.remove('hidden');
        } else {
            startBtn.classList.remove('hidden');
            stopBtn.classList.add('hidden');
        }
    }
}

function showProgressSection(show) {
    const progressSection = document.getElementById('scan-progress-section');
    if (progressSection) {
        if (show) {
            progressSection.classList.remove('hidden');
        } else {
            progressSection.classList.add('hidden');
        }
    }
}

async function executeDoringScan(target, includeSubdomains, delay) {
    const allDorks = [];
    
    // Collect all dorks from selected categories
    for (const categoryId of selectedCategories) {
        const categoryDorks = appData.dorks_by_category[categoryId] || [];
        categoryDorks.forEach(dorkTemplate => {
            allDorks.push({
                categoryId,
                categoryName: appData.categories[categoryId],
                query: dorkTemplate.replace('{target}', target),
                originalQuery: dorkTemplate,
                risk: appData.risk_mappings[categoryId] || 'Low'
            });
        });
    }
    
    const totalDorks = allDorks.length;
    let processedDorks = 0;
    let foundResults = 0;
    
    showToast(`Starting scan with ${totalDorks} dorks`);
    
    // Process each dork
    for (let i = 0; i < allDorks.length && isScanning; i++) {
        const dork = allDorks[i];
        
        // Update progress
        processedDorks++;
        const progress = (processedDorks / totalDorks) * 100;
        
        updateScanProgress(progress, processedDorks, foundResults, dork.categoryName);
        
        try {
            // Simulate search engine query
            const results = await simulateSearchEngineQuery(dork);
            
            if (results.length > 0) {
                foundResults += results.length;
                scanResults.push(...results);
                
                // Add results to UI in real-time
                renderScanResults();
                
                // Auto-switch to results tab when first results are found
                if (foundResults === results.length) {
                    switchTab('results');
                }
            }
        } catch (error) {
            console.error('Query error for dork:', dork, error);
        }
        
        // Delay between requests
        if (i < allDorks.length - 1 && isScanning) {
            await sleep(delay);
        }
    }
    
    if (isScanning) {
        showToast(`Scan complete! Found ${foundResults} results across ${selectedCategories.size} categories`);
        updateScanProgress(100, processedDorks, foundResults, 'Complete');
    }
}

async function simulateSearchEngineQuery(dork) {
    // Simulate realistic search results based on dork type
    const results = [];
    
    // Simulate random chance of finding results (more realistic)
    const findChance = getResultProbability(dork);
    
    if (Math.random() < findChance) {
        const numResults = Math.floor(Math.random() * 3) + 1; // 1-3 results
        
        for (let i = 0; i < numResults; i++) {
            const result = generateSimulatedResult(dork, i);
            results.push(result);
        }
    }
    
    return results;
}

function getResultProbability(dork) {
    // Higher chance for certain types of dorks
    if (dork.query.includes('login') || dork.query.includes('admin')) return 0.4;
    if (dork.query.includes('index of')) return 0.3;
    if (dork.query.includes('filetype:txt')) return 0.25;
    if (dork.query.includes('password') || dork.query.includes('config')) return 0.2;
    if (dork.query.includes('error') || dork.query.includes('apache')) return 0.35;
    return 0.15; // Default probability
}

function generateSimulatedResult(dork, index) {
    const domain = extractDomainFromQuery(dork.query);
    const paths = generateRealisticPaths(dork);
    const path = paths[index % paths.length];
    
    return {
        id: Date.now() + Math.random(),
        url: `https://${domain}${path}`,
        title: generateTitle(dork, path),
        description: generateDescription(dork),
        query: dork.query,
        originalQuery: dork.originalQuery,
        categoryId: dork.categoryId,
        categoryName: dork.categoryName,
        risk: dork.risk,
        status: 'found',
        timestamp: new Date().toISOString()
    };
}

function extractDomainFromQuery(query) {
    const match = query.match(/site:([^\s]+)/);
    return match ? match[1] : 'example.com';
}

function generateRealisticPaths(dork) {
    if (dork.query.includes('admin')) return ['/admin/', '/admin/login.php', '/administrator/', '/admin/index.php'];
    if (dork.query.includes('login')) return ['/login.php', '/wp-login.php', '/user/login', '/account/login'];
    if (dork.query.includes('config')) return ['/config.php', '/wp-config.php', '/app/config.php', '/config/database.php'];
    if (dork.query.includes('index of')) return ['/backup/', '/config/', '/private/', '/temp/', '/logs/'];
    if (dork.query.includes('filetype:pdf')) return ['/docs/confidential.pdf', '/files/internal.pdf', '/reports/sensitive.pdf'];
    if (dork.query.includes('error')) return ['/error.php', '/debug.php', '/test.php'];
    if (dork.query.includes('apache')) return ['/', '/server-status', '/server-info'];
    return ['/', '/index.php', '/home.php', '/main.php'];
}

function generateTitle(dork, path) {
    if (dork.query.includes('admin')) return 'Admin Panel - Login Required';
    if (dork.query.includes('login')) return 'User Login - Please Sign In';
    if (dork.query.includes('config')) return 'Configuration File';
    if (dork.query.includes('index of')) return `Index of ${path}`;
    if (dork.query.includes('error')) return 'Error Page - Debug Information';
    if (dork.query.includes('apache')) return 'Apache HTTP Server Test Page';
    return 'Web Page';
}

function generateDescription(dork) {
    if (dork.query.includes('admin')) return 'Administrative login interface for website management.';
    if (dork.query.includes('login')) return 'User authentication portal with username and password fields.';
    if (dork.query.includes('config')) return 'Configuration file containing system settings and parameters.';
    if (dork.query.includes('index of')) return 'Directory listing showing file and folder contents.';
    if (dork.query.includes('error')) return 'Error page displaying system debugging information.';
    if (dork.query.includes('apache')) return 'Apache web server default or status page.';
    return 'Web page containing relevant information.';
}

function updateScanProgress(progress, scanned, found, category) {
    const progressFill = document.getElementById('progress-fill');
    const progressText = document.getElementById('progress-text');
    const scannedDorks = document.getElementById('scanned-dorks');
    const foundResults = document.getElementById('found-results');
    const currentCategory = document.getElementById('current-category');
    
    if (progressFill) progressFill.style.width = `${progress}%`;
    if (progressText) progressText.textContent = `${Math.round(progress)}% - ${category}`;
    if (scannedDorks) scannedDorks.textContent = scanned;
    if (foundResults) foundResults.textContent = found;
    if (currentCategory) currentCategory.textContent = category;
}

function stopScan() {
    isScanning = false;
    updateScanUI(false);
    showToast('Scan stopped by user');
}

function renderScanResults() {
    const container = document.getElementById('results-container');
    if (!container) return;
    
    if (scanResults.length === 0) {
        container.innerHTML = '<div class="empty-state">No scan results yet. Start a scan to see results here.</div>';
        return;
    }
    
    // Apply current filters
    const filteredResults = filterScanResults();
    
    if (filteredResults.length === 0) {
        container.innerHTML = '<div class="empty-state">No results match the current filter criteria.</div>';
        return;
    }
    
    container.innerHTML = '';
    
    filteredResults.forEach(result => {
        const card = document.createElement('div');
        card.className = 'result-card';
        card.addEventListener('click', () => showResultDetails(result));
        
        card.innerHTML = `
            <div class="result-header">
                <div class="result-url">${result.url}</div>
                <div class="result-status status-${result.status}">${result.status.toUpperCase()}</div>
            </div>
            <div class="result-title">${result.title}</div>
            <div class="result-description">${result.description}</div>
            <div class="result-meta">
                <span class="result-risk risk-${result.risk.toLowerCase()}">${result.risk}</span>
                <span class="result-category">${result.categoryName}</span>
            </div>
        `;
        
        container.appendChild(card);
    });
}

function filterScanResults() {
    const searchInput = document.getElementById('results-search');
    const categoryFilter = document.getElementById('results-category-filter');
    const riskFilter = document.getElementById('results-risk-filter');
    
    const searchTerm = searchInput ? searchInput.value.toLowerCase() : '';
    const categoryFilterValue = categoryFilter ? categoryFilter.value : '';
    const riskFilterValue = riskFilter ? riskFilter.value : '';
    
    return scanResults.filter(result => {
        const matchesSearch = !searchTerm || 
            result.url.toLowerCase().includes(searchTerm) ||
            result.title.toLowerCase().includes(searchTerm) ||
            result.description.toLowerCase().includes(searchTerm);
            
        const matchesCategory = !categoryFilterValue || result.categoryId === categoryFilterValue;
        const matchesRisk = !riskFilterValue || result.risk === riskFilterValue;
        
        return matchesSearch && matchesCategory && matchesRisk;
    });
}

function filterResults() {
    renderScanResults();
}

function showResultDetails(result) {
    currentResult = result;
    
    const urlEl = document.getElementById('modal-url');
    const titleEl = document.getElementById('modal-title');
    const descEl = document.getElementById('modal-description');
    const queryEl = document.getElementById('modal-query');
    const riskEl = document.getElementById('modal-risk');
    const categoryEl = document.getElementById('modal-category');
    const modal = document.getElementById('result-modal');
    
    if (urlEl) urlEl.textContent = result.url;
    if (titleEl) titleEl.textContent = result.title;
    if (descEl) descEl.textContent = result.description;
    if (queryEl) queryEl.textContent = result.query;
    if (riskEl) riskEl.innerHTML = `<span class="result-risk risk-${result.risk.toLowerCase()}">${result.risk} Risk</span>`;
    if (categoryEl) categoryEl.textContent = result.categoryName;
    
    if (modal) modal.classList.remove('hidden');
}

function closeModal() {
    const modal = document.getElementById('result-modal');
    if (modal) modal.classList.add('hidden');
    currentResult = null;
}

function visitResult() {
    if (currentResult) {
        window.open(currentResult.url, '_blank');
    }
}

function copyUrl() {
    if (currentResult) {
        copyToClipboard(currentResult.url);
        showToast('URL copied to clipboard');
    }
}

function exportResults() {
    if (scanResults.length === 0) {
        showToast('No results to export');
        return;
    }
    
    const filteredResults = filterScanResults();
    const exportData = {
        timestamp: new Date().toISOString(),
        total_results: filteredResults.length,
        results: filteredResults.map(result => ({
            url: result.url,
            title: result.title,
            description: result.description,
            query: result.query,
            category: result.categoryName,
            risk: result.risk,
            timestamp: result.timestamp
        }))
    };
    
    const jsonStr = JSON.stringify(exportData, null, 2);
    const blob = new Blob([jsonStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    
    const a = document.createElement('a');
    a.href = url;
    a.download = `dorking-results-${new Date().toISOString().split('T')[0]}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    
    showToast('Results exported successfully');
}

function clearResults() {
    if (scanResults.length === 0) {
        showToast('No results to clear');
        return;
    }
    
    scanResults = [];
    renderScanResults();
    showToast('All results cleared');
}

function copyToClipboard(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).catch(err => {
            fallbackCopy(text);
        });
    } else {
        fallbackCopy(text);
    }
}

function fallbackCopy(text) {
    const textArea = document.createElement('textarea');
    textArea.value = text;
    textArea.style.position = 'fixed';
    textArea.style.top = '-1000px';
    textArea.style.left = '-1000px';
    document.body.appendChild(textArea);
    textArea.focus();
    textArea.select();
    
    try {
        document.execCommand('copy');
    } catch (err) {
        console.error('Copy failed:', err);
    }
    
    document.body.removeChild(textArea);
}

function showToast(message) {
    const toast = document.getElementById('toast');
    const messageEl = toast ? toast.querySelector('.toast-message') : null;
    
    if (toast && messageEl) {
        messageEl.textContent = message;
        toast.classList.remove('hidden');
        
        setTimeout(() => {
            toast.classList.add('hidden');
        }, 3000);
    }
}

function handleKeyboardShortcuts(e) {
    if (e.key === 'Escape') {
        closeModal();
    }
    
    if (e.ctrlKey && e.key === 'Enter') {
        if (!isScanning) {
            startScan();
        }
    }
}

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}