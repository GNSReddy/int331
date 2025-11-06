// Demo users
const demoUsers = {
    'user1': { password: 'password123', isAdmin: false },
    'admin': { password: 'admin123', isAdmin: true }
};

// Current user state
let currentUser = null;
let files = [];

// DOM ready
document.addEventListener('DOMContentLoaded', function() {
    // Initialize tabs
    const tabEls = document.querySelectorAll('button[data-bs-toggle="tab"]');
    tabEls.forEach(tabEl => {
        tabEl.addEventListener('click', function(event) {
            event.preventDefault();
            const tabTarget = this.getAttribute('data-bs-target');
            const tabPane = document.querySelector(tabTarget);
            const activeTabPanes = document.querySelectorAll('.tab-pane.show.active');
            activeTabPanes.forEach(pane => {
                pane.classList.remove('show', 'active');
            });
            tabPane.classList.add('show', 'active');
            
            const activeTabs = document.querySelectorAll('.nav-link.active');
            activeTabs.forEach(tab => {
                tab.classList.remove('active');
            });
            this.classList.add('active');
        });
    });
    
    // Login form
    document.getElementById('loginForm').addEventListener('submit', function(e) {
        e.preventDefault();
        const username = document.getElementById('demoUsername').value;
        const password = document.getElementById('demoPassword').value;
        handleLogin(username, password);
    });
    
    // Modal login form
    document.getElementById('modalLoginForm').addEventListener('submit', function(e) {
        e.preventDefault();
        const username = document.getElementById('modalUsername').value;
        const password = document.getElementById('modalPassword').value;
        handleLogin(username, password);
        const modal = bootstrap.Modal.getInstance(document.getElementById('loginModal'));
        modal.hide();
    });
    
    // Register form
    document.getElementById('modalRegisterForm').addEventListener('submit', function(e) {
        e.preventDefault();
        const username = document.getElementById('regUsername').value;
        const password = document.getElementById('regPassword').value;
        const confirmPassword = document.getElementById('regConfirmPassword').value;
        
        if (password !== confirmPassword) {
            alert('Passwords do not match!');
            return;
        }
        
        addAuthLog(`User ${username} registered successfully`, true);
        const modal = bootstrap.Modal.getInstance(document.getElementById('registerModal'));
        modal.hide();
        showLoginModal();
    });
    
    // Upload form
    document.getElementById('uploadForm').addEventListener('submit', function(e) {
        e.preventDefault();
        const fileInput = document.getElementById('fileUpload');
        if (fileInput.files.length === 0) return;
        
        const file = fileInput.files[0];
        simulateFileUpload(file);
    });
});

// Show login modal
function showLoginModal() {
    const modal = new bootstrap.Modal(document.getElementById('loginModal'));
    modal.show();
}

// Show register modal
function showRegisterModal() {
    const modal = new bootstrap.Modal(document.getElementById('registerModal'));
    modal.show();
}

// Handle login
function handleLogin(username, password) {
    if (demoUsers[username] && demoUsers[username].password === password) {
        currentUser = {
            username: username,
            isAdmin: demoUsers[username].isAdmin
        };
        
        addAuthLog(`User ${username} logged in successfully`, true);
        alert(`Welcome ${username}! You are now logged in.`);
        
        // Update UI for logged in user
        if (username === 'admin') {
            files = [
                { id: 1, name: 'config.txt', size: '12 KB', date: '2023-05-15' },
                { id: 2, name: 'backup.zip', size: '45 MB', date: '2023-05-10' }
            ];
        } else {
            files = [
                { id: 1, name: 'document.pdf', size: '2.3 MB', date: '2023-05-12' },
                { id: 2, name: 'presentation.pptx', size: '15 MB', date: '2023-05-08' }
            ];
        }
        
        updateFileList();
    } else {
        addAuthLog(`Failed login attempt for user ${username}`, false);
        alert('Invalid username or password!');
    }
}

// Add entry to auth log
function addAuthLog(message, success) {
    const authLog = document.getElementById('authLog');
    const logEntry = document.createElement('div');
    logEntry.className = `log-entry ${success ? 'success' : 'danger'}`;
    logEntry.innerHTML = `<strong>${new Date().toLocaleTimeString()}:</strong> ${message}`;
    authLog.appendChild(logEntry);
    authLog.scrollTop = authLog.scrollHeight;
}

// Add entry to security log
function addSecurityLog(message, type = 'info') {
    const securityLog = document.getElementById('securityLog');
    const logEntry = document.createElement('div');
    logEntry.className = `log-entry ${type}`;
    logEntry.innerHTML = `<strong>${new Date().toLocaleTimeString()}:</strong> ${message}`;
    securityLog.appendChild(logEntry);
    securityLog.scrollTop = securityLog.scrollHeight;
}

// Simulate file upload
function simulateFileUpload(file) {
    const progressBar = document.querySelector('#uploadProgress .progress-bar');
    const uploadProgress = document.getElementById('uploadProgress');
    
    uploadProgress.style.display = 'block';
    progressBar.style.width = '0%';
    
    let progress = 0;
    const interval = setInterval(() => {
        progress += Math.random() * 10;
        if (progress > 100) progress = 100;
        progressBar.style.width = `${progress}%`;
        
        if (progress === 100) {
            clearInterval(interval);
            setTimeout(() => {
                uploadProgress.style.display = 'none';
                
                // Add the file to the list
                const newFile = {
                    id: files.length + 1,
                    name: file.name,
                    size: formatFileSize(file.size),
                    date: new Date().toISOString().split('T')[0]
                };
                files.push(newFile);
                updateFileList();
                
                addSecurityLog(`File "${file.name}" uploaded successfully`, 'success');
            }, 500);
        }
    }, 200);
}

// Format file size
function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// Update file list display
function updateFileList() {
    const fileList = document.getElementById('fileList');
    fileList.innerHTML = '';
    
    if (files.length === 0) {
        fileList.innerHTML = '<div class="list-group-item">No files uploaded yet</div>';
        return;
    }
    
    files.forEach(file => {
        const fileItem = document.createElement('div');
        fileItem.className = 'list-group-item list-group-item-action';
        fileItem.innerHTML = `
            <div class="d-flex justify-content-between">
                <div>
                    <h6 class="mb-1">${file.name}</h6>
                    <small class="text-muted">${file.size} - ${file.date}</small>
                </div>
                <div>
                    <input type="radio" name="selectedFile" value="${file.id}" onchange="toggleFileActions()">
                </div>
            </div>
        `;
        fileList.appendChild(fileItem);
    });
}

// Toggle file actions buttons
function toggleFileActions() {
    const fileActions = document.getElementById('fileActions');
    const selectedFile = document.querySelector('input[name="selectedFile"]:checked');
    
    if (selectedFile) {
        fileActions.classList.remove('d-none');
    } else {
        fileActions.classList.add('d-none');
    }
}

// Download selected file
function downloadSelectedFile() {
    const selectedFileId = document.querySelector('input[name="selectedFile"]:checked').value;
    const file = files.find(f => f.id == selectedFileId);
    
    if (file) {
        addSecurityLog(`File "${file.name}" download initiated`, 'success');
        alert(`Simulating download of ${file.name}`);
    }
}

// Delete selected file
function deleteSelectedFile() {
    const selectedFileId = document.querySelector('input[name="selectedFile"]:checked').value;
    const fileIndex = files.findIndex(f => f.id == selectedFileId);
    
    if (fileIndex !== -1) {
        const fileName = files[fileIndex].name;
        files.splice(fileIndex, 1);
        updateFileList();
        document.getElementById('fileActions').classList.add('d-none');
        addSecurityLog(`File "${fileName}" deleted`, 'success');
    }
}

// Simulate malware scan
function simulateMalwareScan() {
    const malwareScanResult = document.getElementById('malwareScanResult');
    malwareScanResult.innerHTML = '<div class="alert alert-info">Scanning files...</div>';
    
    setTimeout(() => {
        const isInfected = Math.random() > 0.8; // 20% chance of infection
        if (isInfected) {
            malwareScanResult.innerHTML = `
                <div class="alert alert-danger">
                    <h5>Malware Detected!</h5>
                    <p>File "suspicious.exe" contains known malware (Trojan.Generic.123456)</p>
                    <button class="btn btn-sm btn-danger">Quarantine File</button>
                </div>
            `;
            addSecurityLog('Malware detected in file "suspicious.exe"', 'danger');
        } else {
            malwareScanResult.innerHTML = `
                <div class="alert alert-success">
                    <h5>Scan Complete</h5>
                    <p>No malware detected in any files</p>
                </div>
            `;
            addSecurityLog('Malware scan completed - no threats found', 'success');
        }
    }, 2000);
}

// Simulate suspicious activity
function simulateSuspiciousActivity() {
    addSecurityLog('Multiple failed login attempts detected from IP 192.168.1.100', 'warning');
    addSecurityLog('Brute force attack detected - IP 192.168.1.100 blocked', 'danger');
    setTimeout(() => {
        addSecurityLog('Admin notified about suspicious activity', 'info');
    }, 1000);
}

// Run performance test
function runPerformanceTest() {
    const performanceMetrics = document.getElementById('performanceMetrics');
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
                    <table class="table">
                        <thead>
                            <tr>
                                <th>Operation</th>
                                <th>Time</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr>
                                <td>File Read (1MB)</td>
                                <td>12ms</td>
                            </tr>
                            <tr>
                                <td>File Write (1MB)</td>
                                <td>18ms</td>
                            </tr>
                            <tr>
                                <td>Encryption (AES-256)</td>
                                <td>25ms</td>
                            </tr>
                            <tr>
                                <td>Directory Listing</td>
                                <td>8ms</td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>
            <div class="alert alert-success">
                Performance is 35% faster than traditional file systems
            </div>
        `;
        addSecurityLog('Performance test completed - system operating optimally', 'success');
    }, 3000);
}