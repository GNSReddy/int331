'use strict';

// Global Variables
const demoUsers = {
    admin: { password: 'admin123', isAdmin: true },
    user: { password: 'user123', isAdmin: false }
};

let currentUser = null;
const files = [];
let flowchartStep = 0;
let flowchartInterval = null;

// DOM Ready Handler
document.addEventListener('DOMContentLoaded', function() {
    initializeEventListeners();
    initFlowchart();
    
    // Check for saved dark mode preference
    if (localStorage.getItem('darkMode') === 'true') {
        toggleDarkMode();
    }
    
    // Initialize application
    initApplication();
});

function initializeEventListeners() {
    // Authentication Forms
    document.getElementById('loginForm')?.addEventListener('submit', function(e) {
        e.preventDefault();
        const username = document.getElementById('demoUsername').value.trim();
        const password = document.getElementById('demoPassword').value.trim();
        handleLogin(username, password);
    });

    document.getElementById('modalLoginForm')?.addEventListener('submit', function(e) {
        e.preventDefault();
        const username = document.getElementById('modalUsername').value.trim();
        const password = document.getElementById('modalPassword').value.trim();
        if (handleLogin(username, password)) {
            const modal = bootstrap.Modal.getInstance(document.getElementById('loginModal'));
            modal.hide();
        }
    });

    document.getElementById('modalRegisterForm')?.addEventListener('submit', function(e) {
        e.preventDefault();
        const username = document.getElementById('regUsername').value.trim();
        const password = document.getElementById('regPassword').value.trim();
        const confirmPassword = document.getElementById('regConfirmPassword').value.trim();
        
        if (!username || !password) {
            addLogEntry('authLog', 'Username and password are required', 'danger');
            return;
        }
        
        if (password !== confirmPassword) {
            addLogEntry('authLog', 'Passwords do not match!', 'danger');
            return;
        }
        
        if (demoUsers[username]) {
            addLogEntry('authLog', 'Username already exists', 'danger');
            return;
        }
        
        demoUsers[username] = { password: password, isAdmin: false };
        addLogEntry('authLog', `User ${username} registered successfully`, 'success');
        const modal = bootstrap.Modal.getInstance(document.getElementById('registerModal'));
        modal.hide();
        showLoginModal();
    });

    // File Operations
    document.getElementById('uploadForm')?.addEventListener('submit', function(e) {
        e.preventDefault();
        handleFileUpload();
    });

    // Navigation Buttons
    document.getElementById('showLoginModal')?.addEventListener('click', showLoginModal);
    document.getElementById('showRegisterModal')?.addEventListener('click', showRegisterModal);
    document.getElementById('darkModeToggle')?.addEventListener('click', toggleDarkMode);
    document.getElementById('runPerformanceTest')?.addEventListener('click', runPerformanceTest);
    document.getElementById('startFlowchart')?.addEventListener('click', startFlowchartAnimation);
    document.getElementById('resetFlowchart')?.addEventListener('click', resetFlowchartAnimation);
    document.getElementById('scanForThreats')?.addEventListener('click', simulateMalwareScan);
    document.getElementById('simulateAttack')?.addEventListener('click', simulateSuspiciousActivity);
    document.getElementById('createBackup')?.addEventListener('click', createBackup);
    document.getElementById('restoreSystem')?.addEventListener('click', restoreSystem);
    document.getElementById('downloadFile')?.addEventListener('click', downloadSelectedFile);
    document.getElementById('deleteFile')?.addEventListener('click', deleteSelectedFile);
    document.getElementById('batchUpload')?.addEventListener('click', handleBatchUpload);
}

// Authentication Functions
function showLoginModal() {
    const modal = new bootstrap.Modal(document.getElementById('loginModal'));
    modal.show();
}

function showRegisterModal() {
    const modal = new bootstrap.Modal(document.getElementById('registerModal'));
    modal.show();
}

function handleLogin(username, password) {
    try {
        if (!username || !password) {
            throw new Error('Username and password are required');
        }
        
        const user = demoUsers[username];
        if (user && user.password === password) {
            currentUser = {
                username: username,
                isAdmin: user.isAdmin
            };
            addLogEntry('authLog', `User ${username} logged in successfully`, 'success');
            
            // Enable file operations
            document.getElementById('fileInput').disabled = false;
            document.getElementById('textToEncrypt').disabled = false;
            updateFileList();
            
            // Enable authenticated features
            document.querySelectorAll('.requires-auth').forEach(el => {
                el.style.opacity = '1';
                el.style.pointerEvents = 'auto';
            });
            
            return true;
        }
        throw new Error('Invalid username or password');
    } catch (error) {
        addLogEntry('authLog', error.message, 'danger');
        return false;
    }
}
// File Management Functions
function handleFileUpload() {
    if (!currentUser) {
        addLogEntry('encryptLog', 'Please login first', 'danger');
        showLoginModal();
        return;
    }
    
    const fileInput = document.getElementById('fileInput');
    const textInput = document.getElementById('textToEncrypt').value.trim();
    
    if (fileInput.files.length === 0 && !textInput) {
        addLogEntry('encryptLog', 'Please select a file or enter text to encrypt', 'warning');
        return;
    }
    
    if (fileInput.files.length > 0) {
        simulateFileUpload(fileInput.files[0]);
    }
    
    if (textInput) {
        handleTextEncryption(textInput);
    }
}

function simulateFileUpload(file) {
    const progressBar = document.getElementById('uploadProgress');
    progressBar.style.display = 'block';
    const bar = progressBar.querySelector('.progress-bar');
    bar.style.width = '0%';
    bar.classList.remove('bg-success', 'bg-danger');
    bar.classList.add('bg-primary');
    
    let progress = 0;
    const interval = setInterval(() => {
        progress += 10;
        bar.style.width = `${progress}%`;
        
        if (progress >= 100) {
            clearInterval(interval);
            setTimeout(() => {
                progressBar.style.display = 'none';
                
                try {
                    const newFile = {
                        id: Date.now(),
                        name: file.name,
                        size: formatFileSize(file.size),
                        date: new Date().toLocaleString(),
                        encrypted: true,
                        type: file.type,
                        content: file
                    };
                    files.push(newFile);
                    addLogEntry('encryptLog', `File "${file.name}" encrypted and uploaded successfully`, 'success');
                    
                    updateFileList();
                    bar.classList.remove('bg-primary');
                    bar.classList.add('bg-success');
                    
                    // Reset form
                    document.getElementById('fileInput').value = '';
                } catch (error) {
                    bar.classList.remove('bg-primary');
                    bar.classList.add('bg-danger');
                    addLogEntry('encryptLog', `Upload failed: ${error.message}`, 'danger');
                }
            }, 500);
        }
    }, 200);
}

function handleTextEncryption(text) {
    try {
        const encryptedText = encryptText(text);
        const newFile = {
            id: Date.now(),
            name: `text-${Date.now()}.txt`,
            size: formatFileSize(new Blob([text]).size),
            date: new Date().toLocaleString(),
            encrypted: true,
            type: 'text/plain',
            content: text,
            encryptedContent: encryptedText
        };
        files.push(newFile);
        addLogEntry('encryptLog', `Text encrypted and stored successfully`, 'success');
        
        updateFileList();
        document.getElementById('textToEncrypt').value = '';
    } catch (error) {
        addLogEntry('encryptLog', `Encryption failed: ${error.message}`, 'danger');
    }
}

function encryptText(text) {
    // Simple encryption for demo purposes (replace with Web Crypto API in production)
    return btoa(encodeURIComponent(text)).split('').reverse().join('');
}

function decryptText(encryptedText) {
    // Simple decryption for demo purposes
    return decodeURIComponent(atob(encryptedText.split('').reverse().join('')));
}

function updateFileList() {
    const fileList = document.getElementById('fileList');
    if (!fileList) return;
    
    fileList.innerHTML = '';
    
    if (files.length === 0) {
        fileList.innerHTML = '<div class="list-group-item">No files uploaded yet</div>';
        document.getElementById('fileActions')?.classList.add('d-none');
        return;
    }
    
    files.forEach(file => {
        const fileItem = document.createElement('div');
        fileItem.className = 'list-group-item list-group-item-action';
        fileItem.innerHTML = `
            <div class="d-flex justify-content-between">
                <div>
                    <h6 class="mb-1">${file.name}</h6>
                    <small class="text-muted">${file.size} - ${file.date} - ${file.encrypted ? 'Encrypted' : 'Not Encrypted'}</small>
                </div>
                <div>
                    <input type="radio" name="selectedFile" value="${file.id}" onchange="window.toggleFileActions()">
                </div>
            </div>
        `;
        fileList.appendChild(fileItem);
    });
}

// Make functions available to window for inline event handlers
window.toggleFileActions = function() {
    const fileActions = document.getElementById('fileActions');
    if (!fileActions) return;
    
    const selectedFile = document.querySelector('input[name="selectedFile"]:checked');
    fileActions.classList.toggle('d-none', !selectedFile);
};

window.downloadSelectedFile = function() {
    try {
        const selectedFileId = document.querySelector('input[name="selectedFile"]:checked')?.value;
        if (!selectedFileId) throw new Error('No file selected');
        
        const file = files.find(f => f.id == selectedFileId);
        if (!file) throw new Error('File not found');
        
        addLogEntry('encryptLog', `Preparing to download "${file.name}"`, 'info');
        
        if (file.type === 'text/plain' && file.encryptedContent) {
            // For demo purposes, show decrypted text in alert
            const decrypted = decryptText(file.encryptedContent);
            alert(`Decrypted content:\n\n${decrypted}`);
        } else {
            // Simulate file download
            alert(`Simulating download of ${file.name}`);
        }
        
        addLogEntry('encryptLog', `Downloaded file "${file.name}"`, 'success');
    } catch (error) {
        addLogEntry('encryptLog', error.message, 'danger');
    }
};

window.deleteSelectedFile = function() {
    try {
        const selectedFileId = document.querySelector('input[name="selectedFile"]:checked')?.value;
        if (!selectedFileId) throw new Error('No file selected');
        
        const fileIndex = files.findIndex(f => f.id == selectedFileId);
        if (fileIndex === -1) throw new Error('File not found');
        
        const fileName = files[fileIndex].name;
        files.splice(fileIndex, 1);
        updateFileList();
        document.getElementById('fileActions')?.classList.add('d-none');
        addLogEntry('encryptLog', `File "${fileName}" deleted`, 'success');
    } catch (error) {
        addLogEntry('encryptLog', error.message, 'danger');
    }
};
// Threat Detection Functions
function simulateMalwareScan() {
    addLogEntry('threatLog', 'Starting threat detection scan...', 'info');
    
    setTimeout(() => {
        const threats = [
            'Scan complete: No threats detected',
            'Warning: Suspicious file pattern detected (possible script injection)',
            'Critical: Potential malware signature found (Trojan:Script/Wacatac.B!ml)'
        ];
        const randomThreat = threats[Math.floor(Math.random() * threats.length)];
        
        if (randomThreat.includes('No threats')) {
            addLogEntry('threatLog', randomThreat, 'success');
        } else if (randomThreat.includes('Warning')) {
            addLogEntry('threatLog', randomThreat, 'warning');
        } else {
            addLogEntry('threatLog', randomThreat, 'danger');
        }
    }, 2000);
}

function simulateSuspiciousActivity() {
    addLogEntry('threatLog', 'Simulating attack scenario...', 'warning');
    
    setTimeout(() => {
        const attacks = [
            'Detected brute force attempt from IP 192.168.1.105 (5 failed attempts in 30 seconds)',
            'Blocked SQL injection attempt in login form',
            'Quarantined suspicious executable file (hash: a1b2c3d4e5f6)'
        ];
        const randomAttack = attacks[Math.floor(Math.random() * attacks.length)];
        addLogEntry('threatLog', randomAttack, 'danger');
        
        setTimeout(() => {
            const responses = [
                'Automatically blocked suspicious IP address',
                'Reset affected account credentials',
                'Isolated and analyzed suspicious file'
            ];
            addLogEntry('threatLog', responses[Math.floor(Math.random() * responses.length)], 'success');
        }, 1000);
    }, 1500);
}

// Performance Functions
function runPerformanceTest() {
    const performanceMetrics = document.getElementById('performanceMetrics');
    if (!performanceMetrics) return;
    
    performanceMetrics.innerHTML = `
        <div class="alert alert-info">
            <h5>Running Performance Tests...</h5>
            <div class="progress progress-thin mt-2">
                <div class="progress-bar progress-bar-striped progress-bar-animated" style="width: 100%"></div>
            </div>
        </div>
    `;
    
    setTimeout(() => {
        performanceMetrics.innerHTML = `
            <div class="card mb-3">
                <div class="card-body">
                    <h5 class="card-title">Performance Test Results</h5>
                    <canvas id="accessTimeChart" height="200"></canvas>
                </div>
            </div>
            <div class="card">
                <div class="card-body">
                    <h5 class="card-title">Throughput Comparison</h5>
                    <canvas id="throughputChart" height="200"></canvas>
                </div>
            </div>
            <div class="alert alert-success mt-3">
                Performance is 35% faster than traditional file systems
            </div>
        `;
        
        initPerformanceCharts();
        addLogEntry('encryptLog', 'Performance test completed - system operating optimally', 'success');
    }, 3000);
}

function initPerformanceCharts() {
    if (typeof Chart === 'undefined') {
        console.error('Chart.js is not loaded');
        return;
    }

    // Access Time Chart
    const accessCtx = document.getElementById('accessTimeChart')?.getContext('2d');
    if (accessCtx) {
        new Chart(accessCtx, {
            type: 'bar',
            data: {
                labels: ['Small Files (1-10KB)', 'Medium Files (10KB-1MB)', 'Large Files (1MB+)'],
                datasets: [{
                    label: 'Access Time (ms)',
                    data: [8, 22, 42],
                    backgroundColor: 'rgba(78, 115, 223, 0.8)',
                    borderColor: 'rgba(78, 115, 223, 1)',
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                scales: {
                    y: {
                        beginAtZero: true,
                        title: {
                            display: true,
                            text: 'Time (ms)'
                        }
                    }
                }
            }
        });
    }

    // Throughput Chart
    const throughputCtx = document.getElementById('throughputChart')?.getContext('2d');
    if (throughputCtx) {
        new Chart(throughputCtx, {
            type: 'line',
            data: {
                labels: ['Traditional', 'Optimized'],
                datasets: [{
                    label: 'Files processed per second',
                    data: [120, 210],
                    backgroundColor: 'rgba(28, 200, 138, 0.2)',
                    borderColor: 'rgba(28, 200, 138, 1)',
                    borderWidth: 2,
                    tension: 0.1
                }]
            },
            options: {
                responsive: true,
                scales: {
                    y: {
                        beginAtZero: true,
                        title: {
                            display: true,
                            text: 'Files/sec'
                        }
                    }
                }
            }
        });
    }
}
// Flowchart Functions
function initFlowchart() {
    const flowchart = document.getElementById('flowchartAnimation');
    if (!flowchart) return;
    
    flowchart.innerHTML = '';
    
    // Define nodes and their positions
    const nodes = [
        { id: 1, title: 'User Authentication', x: 50, y: 50, width: 180, height: 80 },
        { id: 2, title: 'Access Control', x: 50, y: 180, width: 180, height: 80 },
        { id: 3, title: 'File Operations', x: 50, y: 310, width: 180, height: 80 },
        { id: 4, title: 'Performance', x: 300, y: 310, width: 180, height: 80 },
        { id: 5, title: 'Threat Detection', x: 550, y: 310, width: 180, height: 80 },
        { id: 6, title: 'Data Recovery', x: 550, y: 180, width: 180, height: 80 },
        { id: 7, title: 'Audit & Reporting', x: 550, y: 50, width: 180, height: 80 }
    ];
    
    // Define arrows (connections between nodes)
    const arrows = [
        { from: 1, to: 2, x1: 140, y1: 130, x2: 140, y2: 180, angle: 90 },
        { from: 2, to: 3, x1: 140, y1: 260, x2: 140, y2: 310, angle: 90 },
        { from: 3, to: 4, x1: 230, y1: 350, x2: 300, y2: 350, angle: 0 },
        { from: 4, to: 5, x1: 480, y1: 350, x2: 550, y2: 350, angle: 0 },
        { from: 5, to: 6, x1: 640, y1: 350, x2: 640, y2: 260, angle: -90 },
        { from: 6, to: 7, x1: 640, y1: 130, x2: 640, y2: 50, angle: -90 }
    ];
    
    // Create nodes
    nodes.forEach(node => {
        const nodeElement = document.createElement('div');
        nodeElement.className = 'flowchart-node';
        nodeElement.id = `flowchart-node-${node.id}`;
        nodeElement.style.left = `${node.x}px`;
        nodeElement.style.top = `${node.y}px`;
        nodeElement.style.width = `${node.width}px`;
        nodeElement.style.height = `${node.height}px`;
        nodeElement.innerHTML = `<h5>${node.title}</h5>`;
        flowchart.appendChild(nodeElement);
    });
    
    // Create arrows
    arrows.forEach(arrow => {
        const arrowElement = document.createElement('div');
        arrowElement.className = 'flowchart-arrow';
        arrowElement.id = `flowchart-arrow-${arrow.from}-${arrow.to}`;
        arrowElement.style.left = `${arrow.x1}px`;
        arrowElement.style.top = `${arrow.y1}px`;
        arrowElement.style.width = `${Math.abs(arrow.x2 - arrow.x1)}px`;
        arrowElement.style.height = `${Math.abs(arrow.y2 - arrow.y1)}px`;
        arrowElement.style.transform = `rotate(${arrow.angle}deg)`;
        flowchart.appendChild(arrowElement);
    });
}

function startFlowchartAnimation() {
    resetFlowchartAnimation();
    flowchartStep = 0;
    
    const nodes = [1, 2, 3, 4, 5, 6, 7];
    const arrows = ['1-2', '2-3', '3-4', '4-5', '5-6', '6-7'];
    
    if (flowchartInterval) {
        clearInterval(flowchartInterval);
    }
    
    flowchartInterval = setInterval(() => {
        // Highlight current node
        if (flowchartStep > 0) {
            document.getElementById(`flowchart-node-${nodes[flowchartStep-1]}`)?.classList.remove('active');
            document.getElementById(`flowchart-node-${nodes[flowchartStep-1]}`)?.classList.add('completed');
            
            if (flowchartStep > 1) {
                document.getElementById(`flowchart-arrow-${arrows[flowchartStep-2]}`)?.classList.remove('active');
                document.getElementById(`flowchart-arrow-${arrows[flowchartStep-2]}`)?.classList.add('completed');
            }
        }
        
        if (flowchartStep >= nodes.length) {
            clearInterval(flowchartInterval);
            return;
        }
        
        // Activate current node
        document.getElementById(`flowchart-node-${nodes[flowchartStep]}`)?.classList.add('active');
        
        // Activate previous arrow if not first step
        if (flowchartStep > 0) {
            document.getElementById(`flowchart-arrow-${arrows[flowchartStep-1]}`)?.classList.add('active');
        }
        
        // Simulate action for current step
        simulateFlowchartAction(flowchartStep + 1);
        
        flowchartStep++;
    }, 1500);
}

function simulateFlowchartAction(step) {
    const actions = [
        () => addLogEntry('authLog', 'User authentication in progress...', 'info'),
        () => addLogEntry('authLog', 'Verifying access permissions...', 'info'),
        () => addLogEntry('encryptLog', 'Processing file operations...', 'info'),
        () => addLogEntry('encryptLog', 'Optimizing performance...', 'info'),
        () => addLogEntry('threatLog', 'Scanning for threats...', 'info'),
        () => addLogEntry('recoveryLog', 'Setting up recovery points...', 'info'),
        () => addLogEntry('recoveryLog', 'Generating audit reports...', 'info')
    ];
    
    if (actions[step - 1]) {
        actions[step - 1]();
        
        // Add success message after a delay
        setTimeout(() => {
            const successMessages = [
                'User authenticated successfully',
                'Access granted',
                'Files encrypted and stored',
                'Performance optimizations applied',
                'Threat scan completed',
                'Recovery system ready',
                'Audit completed'
            ];
            const logTypes = ['authLog', 'authLog', 'encryptLog', 'encryptLog', 'threatLog', 'recoveryLog', 'recoveryLog'];
            
            addLogEntry(logTypes[step - 1], successMessages[step - 1], 'success');
        }, 800);
    }
}

function resetFlowchartAnimation() {
    clearInterval(flowchartInterval);
    
    // Reset all nodes and arrows
    for (let i = 1; i <= 7; i++) {
        const node = document.getElementById(`flowchart-node-${i}`);
        if (node) {
            node.classList.remove('active', 'completed');
        }
    }
    
    const arrows = ['1-2', '2-3', '3-4', '4-5', '5-6', '6-7'];
    arrows.forEach(arrow => {
        const arrowElement = document.getElementById(`flowchart-arrow-${arrow}`);
        if (arrowElement) {
            arrowElement.classList.remove('active', 'completed');
        }
    });
}

// Helper Functions
function addLogEntry(logId, message, type) {
    const log = document.getElementById(logId);
    if (!log) return;
    
    const entry = document.createElement('div');
    entry.className = `log-entry ${type}`;
    entry.innerHTML = `<strong>${new Date().toLocaleTimeString()}:</strong> ${message}`;
    log.appendChild(entry);
    log.scrollTop = log.scrollHeight;
}

function formatFileSize(bytes) {
    if (typeof bytes !== 'number' || bytes < 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function toggleDarkMode() {
    document.body.classList.toggle('dark-mode');
    localStorage.setItem('darkMode', document.body.classList.contains('dark-mode'));
    
    const darkModeBtn = document.getElementById('darkModeToggle');
    if (darkModeBtn) {
        if (document.body.classList.contains('dark-mode')) {
            darkModeBtn.innerHTML = '<i class="fas fa-sun"></i> Light Mode';
        } else {
            darkModeBtn.innerHTML = '<i class="fas fa-moon"></i> Dark Mode';
        }
    }
}
// Recovery Functions
function createBackup() {
    addLogEntry('recoveryLog', 'Creating system backup...', 'info');
    
    setTimeout(() => {
        addLogEntry('recoveryLog', 'Backup created successfully at ' + new Date().toLocaleString(), 'success');
    }, 2000);
}

function restoreSystem() {
    addLogEntry('recoveryLog', 'Initiating system recovery...', 'warning');
    
    setTimeout(() => {
        addLogEntry('recoveryLog', 'Restoring from latest checkpoint...', 'info');
        
        setTimeout(() => {
            addLogEntry('recoveryLog', 'System recovery completed successfully', 'success');
        }, 2000);
    }, 1000);
}

// Batch File Processing
function handleBatchUpload() {
    const fileInput = document.getElementById('multiFileInput');
    if (!fileInput || fileInput.files.length === 0) {
        addLogEntry('fileLog', 'No files selected for batch processing', 'warning');
        return;
    }
    
    batchProcessFiles(Array.from(fileInput.files), (file, done) => {
        encryptFile(file, (err, encryptedBlob) => {
            if (err) return done(err);
            
            // Simulate upload
            setTimeout(() => {
                files.push({
                    id: Date.now(),
                    name: file.name,
                    size: formatFileSize(file.size),
                    date: new Date().toLocaleString(),
                    encrypted: true,
                    type: file.type,
                    content: file
                });
                updateFileList();
                done();
            }, 1000);
        });
    });
}

function batchProcessFiles(fileList, operation) {
    if (!fileList.length) return;

    const progress = {
        total: fileList.length,
        processed: 0,
        success: 0,
        errors: 0
    };

    const updateProgress = () => {
        const progressElement = document.getElementById('batchProgress');
        if (!progressElement) return;
        
        progressElement.innerHTML = `
            <div class="progress mb-2">
                <div class="progress-bar" style="width: ${(progress.processed/progress.total)*100}%"></div>
            </div>
            <small>Processed ${progress.processed} of ${progress.total} files (${progress.success} success, ${progress.errors} errors)</small>
        `;
    };

    fileList.forEach((file, index) => {
        setTimeout(() => {
            operation(file, (err) => {
                progress.processed++;
                if (err) {
                    progress.errors++;
                    addLogEntry('fileLog', `Error processing ${file.name}: ${err.message}`, 'danger');
                } else {
                    progress.success++;
                    addLogEntry('fileLog', `${file.name} processed successfully`, 'success');
                }
                updateProgress();

                if (progress.processed === progress.total) {
                    const summary = `Batch complete: ${progress.success} succeeded, ${progress.errors} failed`;
                    addLogEntry('fileLog', summary, progress.errors ? 'warning' : 'success');
                }
            });
        }, index * 500); // Stagger operations
    });
}

// System Health Monitoring
function startSystemMonitor() {
    const monitorData = {
        cpu: [],
        memory: [],
        storage: []
    };

    const monitorInterval = setInterval(() => {
        // Simulate system metrics
        monitorData.cpu.push(Math.random() * 100);
        monitorData.memory.push(30 + Math.random() * 70);
        monitorData.storage.push(40 + Math.random() * 60);

        // Keep only last 10 readings
        if (monitorData.cpu.length > 10) {
            monitorData.cpu.shift();
            monitorData.memory.shift();
            monitorData.storage.shift();
        }

        updateSystemMonitor(monitorData);
    }, 2000);

    return () => clearInterval(monitorInterval);
}

function updateSystemMonitor(data) {
    const ctx = document.getElementById('systemHealthChart')?.getContext('2d');
    if (!ctx) return;

    // Destroy previous chart if exists
    if (window.systemHealthChart) {
        window.systemHealthChart.destroy();
    }

    window.systemHealthChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: Array.from({length: data.cpu.length}, (_, i) => i + 1),
            datasets: [
                {
                    label: 'CPU Usage %',
                    data: data.cpu,
                    borderColor: 'rgba(255, 99, 132, 1)',
                    backgroundColor: 'rgba(255, 99, 132, 0.2)',
                    tension: 0.1
                },
                {
                    label: 'Memory Usage %',
                    data: data.memory,
                    borderColor: 'rgba(54, 162, 235, 1)',
                    backgroundColor: 'rgba(54, 162, 235, 0.2)',
                    tension: 0.1
                },
                {
                    label: 'Storage Usage %',
                    data: data.storage,
                    borderColor: 'rgba(75, 192, 192, 1)',
                    backgroundColor: 'rgba(75, 192, 192, 0.2)',
                    tension: 0.1
                }
            ]
        },
        options: {
            responsive: true,
            scales: {
                y: {
                    beginAtZero: true,
                    max: 100
                }
            }
        }
    });
}

// User Session Management
function manageUserSession() {
    const SESSION_TIMEOUT = 15 * 60 * 1000; // 15 minutes
    
    let timeoutId;
    
    const resetTimer = () => {
        clearTimeout(timeoutId);
        timeoutId = setTimeout(logoutUser, SESSION_TIMEOUT);
    };
    
    const logoutUser = () => {
        if (!currentUser) return;
        
        addLogEntry('authLog', 'Session expired - automatic logout', 'warning');
        currentUser = null;
        document.getElementById('fileInput').disabled = true;
        document.getElementById('textToEncrypt').disabled = true;
        document.querySelectorAll('.requires-auth').forEach(el => {
            el.style.opacity = '0.5';
            el.style.pointerEvents = 'none';
        });
    };
    
    // Set up event listeners
    document.addEventListener('mousemove', resetTimer);
    document.addEventListener('keypress', resetTimer);
    document.addEventListener('click', resetTimer);
    
    resetTimer(); // Start the timer
}

// Initialize the application
function initApplication() {
    // Set up initial UI state
    document.getElementById('fileInput').disabled = true;
    document.getElementById('textToEncrypt').disabled = true;
    
    // Initialize charts
    if (typeof Chart !== 'undefined') {
        initPerformanceCharts();
    }
    
    // Start system monitoring
    const stopMonitoring = startSystemMonitor();
    
    // Set up session management
    manageUserSession();
    
    // Clean up on page unload
    window.addEventListener('beforeunload', () => {
        stopMonitoring();
    });
}

// Initialize when DOM is ready
if (document.readyState !== 'loading') {
    initApplication();
} else {
    document.addEventListener('DOMContentLoaded', initApplication);
}
