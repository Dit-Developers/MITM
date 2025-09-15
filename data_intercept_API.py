#!/usr/bin/env python3
"""
CasioMITM - A BurpSuite-like MITM simulation tool
Security analysis training tool with Flask web interface and Firebase logging
"""

import json
import threading
import time
from datetime import datetime
from urllib.parse import urlparse, parse_qs
import socket
import ssl
import re
from http.server import HTTPServer, BaseHTTPRequestHandler
import requests
from flask import Flask, render_template_string, request, jsonify, redirect, url_for
import firebase_admin
from firebase_admin import credentials, db
import os
import base64
from socketserver import ThreadingMixIn

# Configuration
PROXY_PORT = 8080
WEB_PORT = 5000

FIREBASE_CONFIG = {
    "type": "service_account",
    "project_id": "techwiz-7f7ab",
    "private_key_id": "your_private_key_id",  # User needs to get this from Firebase console
    "private_key": "-----BEGIN PRIVATE KEY-----\nYOUR_PRIVATE_KEY_HERE\n-----END PRIVATE KEY-----\n",  # User needs to get this
    "client_email": "firebase-adminsdk-xxxxx@techwiz-7f7ab.iam.gserviceaccount.com",  # User needs to get this
    "client_id": "your_client_id",  # User needs to get this
    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
    "token_uri": "https://oauth2.googleapis.com/token",
    "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
    "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/firebase-adminsdk-xxxxx%40techwiz-7f7ab.iam.gserviceaccount.com"
}

FIREBASE_DATABASE_URL = "https://techwiz-7f7ab-default-rtdb.firebaseio.com"

class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in separate threads"""
    daemon_threads = True

class MITMProxy:
    def __init__(self, port=PROXY_PORT):
        self.port = port
        self.intercepted_requests = []
        self.intercept_enabled = True
        self.firebase_db = None
        self.firebase_connected = False
        self.pending_requests = {}  # Store requests waiting for user action
        self.auto_forward = True  # For simulation purposes
        self.firebase_queue = []  # Queue for offline logging
        
    def init_firebase(self):
        """Initialize Firebase connection with direct configuration"""
        try:
            if not firebase_admin._apps:
                # Create credentials from the config dictionary
                cred = credentials.Certificate(FIREBASE_CONFIG)
                firebase_admin.initialize_app(cred, {
                    'databaseURL': FIREBASE_DATABASE_URL
                })
            
            self.firebase_db = db.reference()
            
            # Test connection by writing a test log
            test_ref = self.firebase_db.child('logs').push({
                'host': 'connection_test',
                'message': 'Firebase connection established',
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            })
            
            # Remove test log
            test_ref.delete()
            
            self.firebase_connected = True
            print("✓ Firebase Realtime Database initialized and connected successfully")
            
            # Process any queued logs
            self.process_firebase_queue()
            return True
            
        except Exception as e:
            print(f"⚠ Firebase initialization failed: {e}")
            print("📋 To enable Firebase logging:")
            print("   1. Go to Firebase Console > Project Settings > Service Accounts")
            print("   2. Generate new private key")
            print("   3. Update FIREBASE_CONFIG in the script with your credentials")
            print("   4. Ensure Realtime Database is enabled")
            self.firebase_connected = False
            return False
    
    def process_firebase_queue(self):
        """Process any queued Firebase logs"""
        if not self.firebase_connected or not self.firebase_queue:
            return
        
        print(f"📤 Processing {len(self.firebase_queue)} queued Firebase logs...")
        for log_data in self.firebase_queue:
            try:
                self.firebase_db.child('logs').push(log_data)
            except Exception as e:
                print(f"Error processing queued log: {e}")
        
        self.firebase_queue.clear()
        print("✓ Firebase queue processed")
    
    def log_to_firebase(self, request_data):
        """Enhanced Firebase logging with user's specified format"""
        log_data = {
            'host': request_data.get('url', 'unknown'),
            'message': f"{request_data.get('method', 'GET')} {request_data.get('url', '')} - Status: {request_data.get('status_code', 'N/A')}",
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
        if self.firebase_connected and self.firebase_db:
            try:
                # Push to logs collection with auto-generated key (like -OZrt-J7sn6gEkjVRXaP)
                self.firebase_db.child('logs').push(log_data)
                print(f"📤 Logged to Firebase: {request_data.get('method')} {request_data.get('url')}")
            except Exception as e:
                print(f"Firebase logging error: {e}")
                # Add to queue for later processing
                self.firebase_queue.append(log_data)
        else:
            # Add to queue if Firebase not connected
            self.firebase_queue.append(log_data)
            if len(self.firebase_queue) > 100:  # Limit queue size
                self.firebase_queue.pop(0)
    
    def get_firebase_stats(self):
        """Get Firebase connection statistics"""
        return {
            'connected': self.firebase_connected,
            'queued_logs': len(self.firebase_queue),
            'database_url': FIREBASE_DATABASE_URL,
            'project_id': FIREBASE_CONFIG.get('project_id', 'Not configured')
        }
    
    def modify_request(self, request_data, modifications):
        """Apply modifications to a request"""
        if 'url' in modifications:
            request_data['url'] = modifications['url']
        if 'headers' in modifications:
            request_data['headers'].update(modifications['headers'])
        if 'body' in modifications:
            request_data['body'] = modifications['body']
        if 'method' in modifications:
            request_data['method'] = modifications['method']
        
        request_data['modified'] = True
        return request_data

class ProxyHandler(BaseHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        self.proxy_instance = kwargs.pop('proxy_instance', None)
        super().__init__(*args, **kwargs)
    
    def log_message(self, format, *args):
        """Suppress default HTTP server logging"""
        pass
    
    def do_CONNECT(self):
        """Handle HTTPS CONNECT method for SSL tunneling"""
        try:
            # Parse the target host and port
            host, port = self.path.split(':')
            port = int(port)
            
            # Create connection to target server
            target_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            target_socket.connect((host, port))
            
            # Send 200 Connection Established
            self.send_response(200, 'Connection Established')
            self.end_headers()
            
            # Start tunneling data between client and server
            self.tunnel_data(self.connection, target_socket)
            
        except Exception as e:
            self.send_error(500, f"CONNECT failed: {str(e)}")
    
    def tunnel_data(self, client_socket, target_socket):
        """Tunnel data between client and target for HTTPS"""
        def forward_data(source, destination):
            try:
                while True:
                    data = source.recv(4096)
                    if not data:
                        break
                    destination.send(data)
            except:
                pass
            finally:
                source.close()
                destination.close()
        
        # Start forwarding in both directions
        client_to_target = threading.Thread(target=forward_data, args=(client_socket, target_socket))
        target_to_client = threading.Thread(target=forward_data, args=(target_socket, client_socket))
        
        client_to_target.daemon = True
        target_to_client.daemon = True
        
        client_to_target.start()
        target_to_client.start()
        
        client_to_target.join()
        target_to_client.join()
    
    def do_GET(self):
        self.handle_request()
    
    def do_POST(self):
        self.handle_request()
    
    def do_PUT(self):
        self.handle_request()
    
    def do_DELETE(self):
        self.handle_request()
    
    def do_HEAD(self):
        self.handle_request()
    
    def do_OPTIONS(self):
        self.handle_request()
    
    def handle_request(self):
        """Enhanced request handling with better error handling and logging"""
        try:
            # Parse the request
            url = self.path
            if not url.startswith('http'):
                host = self.headers.get('Host', 'localhost')
                scheme = 'https' if self.command == 'CONNECT' else 'http'
                url = f"{scheme}://{host}{url}"
            
            # Read request body
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length) if content_length > 0 else b''
            
            # Create request data with enhanced information
            request_data = {
                'id': len(self.proxy_instance.intercepted_requests) + 1,
                'timestamp': datetime.now().isoformat(),
                'method': self.command,
                'url': url,
                'headers': dict(self.headers),
                'body': body.decode('utf-8', errors='ignore'),
                'source_ip': self.client_address[0],
                'source_port': self.client_address[1],
                'intercepted': True,
                'modified': False,
                'user_agent': self.headers.get('User-Agent', 'Unknown'),
                'content_type': self.headers.get('Content-Type', ''),
                'content_length': content_length
            }
            
            # Add to intercepted requests
            self.proxy_instance.intercepted_requests.append(request_data)
            
            # Enhanced interception logic
            if self.proxy_instance.intercept_enabled and not self.proxy_instance.auto_forward:
                print(f"🔍 Intercepted: {self.command} {url}")
                # Store for manual forwarding
                self.proxy_instance.pending_requests[request_data['id']] = request_data
                # In a real implementation, this would wait for user action
                # For simulation, we'll auto-forward after a short delay
                time.sleep(0.5)
            
            # Forward the request with enhanced error handling
            self.forward_request(request_data)
            
        except Exception as e:
            print(f"Error handling request: {e}")
            self.send_error(500, f"Proxy Error: {str(e)}")
    
    def forward_request(self, request_data):
        """Forward request with enhanced capabilities"""
        try:
            url = request_data['url']
            
            # Protocol switching capability (HTTP to HTTPS)
            if 'force-https' in request_data.get('headers', {}):
                url = url.replace('http://', 'https://')
                request_data['url'] = url
                request_data['modified'] = True
            
            # Prepare headers (exclude hop-by-hop headers)
            headers = {}
            hop_by_hop = ['connection', 'keep-alive', 'proxy-authenticate', 
                         'proxy-authorization', 'te', 'trailers', 'upgrade']
            
            for key, value in request_data['headers'].items():
                if key.lower() not in hop_by_hop:
                    headers[key] = value
            
            # Remove proxy-specific headers
            headers.pop('Host', None)
            
            # Make the actual request with timeout and better error handling
            response = requests.request(
                method=request_data['method'],
                url=url,
                headers=headers,
                data=request_data['body'].encode('utf-8') if request_data['body'] else None,
                allow_redirects=False,
                timeout=30,
                verify=False,  # For testing purposes
                stream=True
            )
            
            # Update request data with response
            response_body = ""
            try:
                # Read response content with size limit
                content = response.content
                if len(content) > 10000:  # Limit to 10KB for display
                    response_body = content[:10000].decode('utf-8', errors='ignore') + "... (truncated)"
                else:
                    response_body = content.decode('utf-8', errors='ignore')
            except:
                response_body = "(binary content)"
            
            request_data.update({
                'response_headers': dict(response.headers),
                'response_body': response_body,
                'status_code': response.status_code,
                'intercepted': False,
                'response_time': datetime.now().isoformat()
            })
            
            # Log to Firebase
            self.proxy_instance.log_to_firebase(request_data)
            
            # Send response back to client
            self.send_response(response.status_code)
            
            # Forward response headers
            for header, value in response.headers.items():
                if header.lower() not in ['connection', 'transfer-encoding', 'content-encoding']:
                    self.send_header(header, value)
            
            self.end_headers()
            
            # Forward response body
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    self.wfile.write(chunk)
            
            print(f"✓ Forwarded: {request_data['method']} {url} -> {response.status_code}")
            
        except requests.exceptions.Timeout:
            print(f"⏰ Timeout: {request_data['method']} {url}")
            self.send_error(504, "Gateway Timeout")
        except requests.exceptions.ConnectionError:
            print(f"🔌 Connection Error: {request_data['method']} {url}")
            self.send_error(502, "Bad Gateway")
        except Exception as e:
            print(f"❌ Error forwarding request: {e}")
            self.send_error(500, f"Proxy Error: {str(e)}")

# Flask Web Interface
app = Flask(__name__)
proxy_instance = MITMProxy()

# Enhanced HTML Template with Firebase status
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CasioMITM - Security Analysis Tool</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        :root {
            --primary-orange: #ff6b35;
            --secondary-orange: #ff8c42;
            --dark-bg: #1a1a1a;
            --darker-bg: #0d1117;
            --card-bg: #21262d;
            --border-color: #30363d;
            --text-primary: #f0f6fc;
            --text-secondary: #8b949e;
        }
        
        body {
            background-color: var(--dark-bg);
            color: var(--text-primary);
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        
        .navbar {
            background-color: var(--darker-bg) !important;
            border-bottom: 2px solid var(--primary-orange);
        }
        
        .navbar-brand {
            color: var(--primary-orange) !important;
            font-weight: bold;
            font-size: 1.5rem;
        }
        
        .card {
            background-color: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 8px;
        }
        
        .card-header {
            background-color: var(--darker-bg);
            border-bottom: 1px solid var(--border-color);
            color: var(--primary-orange);
            font-weight: 600;
        }
        
        .btn-primary {
            background-color: var(--primary-orange);
            border-color: var(--primary-orange);
        }
        
        .btn-primary:hover {
            background-color: var(--secondary-orange);
            border-color: var(--secondary-orange);
        }
        
        .btn-outline-primary {
            color: var(--primary-orange);
            border-color: var(--primary-orange);
        }
        
        .btn-outline-primary:hover {
            background-color: var(--primary-orange);
            border-color: var(--primary-orange);
        }
        
        .table-dark {
            --bs-table-bg: var(--card-bg);
            --bs-table-border-color: var(--border-color);
        }
        
        .table-dark th {
            background-color: var(--darker-bg);
            color: var(--primary-orange);
        }
        
        .status-intercepted {
            color: #ffa500;
        }
        
        .status-forwarded {
            color: #28a745;
        }
        
        .method-get { color: #28a745; }
        .method-post { color: #ffc107; }
        .method-put { color: #17a2b8; }
        .method-delete { color: #dc3545; }
        
        .request-details {
            background-color: var(--darker-bg);
            border-radius: 4px;
            padding: 1rem;
            margin: 1rem 0;
        }
        
        .code-block {
            background-color: #0d1117;
            border: 1px solid var(--border-color);
            border-radius: 4px;
            padding: 1rem;
            font-family: 'Courier New', monospace;
            font-size: 0.9rem;
            overflow-x: auto;
        }
        
        .nav-tabs .nav-link {
            color: var(--text-secondary);
            border-color: var(--border-color);
        }
        
        .nav-tabs .nav-link.active {
            background-color: var(--card-bg);
            border-color: var(--primary-orange);
            color: var(--primary-orange);
        }
        
        .form-control, .form-select {
            background-color: var(--card-bg);
            border-color: var(--border-color);
            color: var(--text-primary);
        }
        
        .form-control:focus, .form-select:focus {
            background-color: var(--card-bg);
            border-color: var(--primary-orange);
            color: var(--text-primary);
            box-shadow: 0 0 0 0.2rem rgba(255, 107, 53, 0.25);
        }
        
        .status-indicator {
            display: inline-block;
            width: 10px;
            height: 10px;
            border-radius: 50%;
            margin-right: 8px;
        }
        
        .status-running { background-color: #28a745; }
        .status-stopped { background-color: #dc3545; }
        .status-warning { background-color: #ffc107; }
        
        .firebase-setup {
            background-color: var(--darker-bg);
            border: 1px solid var(--primary-orange);
            border-radius: 8px;
            padding: 1rem;
            margin: 1rem 0;
        }
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark">
        <div class="container-fluid">
            <a class="navbar-brand" href="#">
                <i class="fas fa-shield-alt"></i> CasioMITM
            </a>
            <div class="navbar-nav ms-auto">
                <span class="navbar-text me-3">
                    <span class="status-indicator status-running"></span>
                    Proxy: localhost:{{ proxy_port }}
                </span>
                <span class="navbar-text">
                    <span class="status-indicator {{ 'status-running' if firebase_stats.connected else 'status-warning' }}"></span>
                    Firebase: {{ 'Connected' if firebase_stats.connected else 'Offline' }}
                </span>
            </div>
        </div>
    </nav>

    <div class="container-fluid mt-4">
        <div class="row">
            <!-- Control Panel -->
            <div class="col-md-3">
                <div class="card">
                    <div class="card-header">
                        <i class="fas fa-cogs"></i> Control Panel
                    </div>
                    <div class="card-body">
                        <div class="mb-3">
                            <button class="btn btn-primary w-100 mb-2" onclick="toggleIntercept()">
                                <i class="fas fa-pause"></i> Toggle Intercept
                            </button>
                            <button class="btn btn-outline-primary w-100 mb-2" onclick="clearLogs()">
                                <i class="fas fa-trash"></i> Clear Logs
                            </button>
                        </div>
                        
                        <div class="mb-3">
                            <label class="form-label">Proxy Port:</label>
                            <input type="number" class="form-control" value="{{ proxy_port }}" readonly>
                        </div>
                        
                        <div class="mb-3">
                            <label class="form-label">Intercept Status:</label>
                            <div class="form-control" id="intercept-status">
                                <span class="status-indicator status-running"></span>
                                Enabled
                            </div>
                        </div>
                        
                        <div class="mb-3">
                            <label class="form-label">Total Requests:</label>
                            <div class="form-control" id="request-count">{{ request_count }}</div>
                        </div>
                        
                        <div class="mb-3">
                            <label class="form-label">Firebase Status:</label>
                            <div class="form-control" id="firebase-status">
                                <span class="status-indicator {{ 'status-running' if firebase_stats.connected else 'status-warning' }}"></span>
                                {{ 'Connected' if firebase_stats.connected else 'Offline' }}
                                {% if firebase_stats.queued_logs > 0 %}
                                <br><small class="text-muted">{{ firebase_stats.queued_logs }} queued</small>
                                {% endif %}
                            </div>
                        </div>
                    </div>
                </div>
                
                <!-- Firebase Setup Card -->
                {% if not firebase_stats.connected %}
                <div class="card mt-3">
                    <div class="card-header">
                        <i class="fas fa-database"></i> Firebase Setup
                    </div>
                    <div class="card-body">
                        <div class="firebase-setup">
                            <h6><i class="fas fa-info-circle"></i> Setup Firebase Logging</h6>
                            <ol class="small">
                                <li>Go to <a href="https://console.firebase.google.com" target="_blank" class="text-decoration-none" style="color: var(--primary-orange);">Firebase Console</a></li>
                                <li>Create/select project</li>
                                <li>Enable Firestore Database</li>
                                <li>Go to Project Settings → Service Accounts</li>
                                <li>Generate private key</li>
                                <li>Save as <code>firebase-credentials.json</code></li>
                                <li>Restart CasioMITM</li>
                            </ol>
                            <button class="btn btn-outline-primary btn-sm w-100" onclick="checkFirebaseStatus()">
                                <i class="fas fa-sync"></i> Check Status
                            </button>
                        </div>
                    </div>
                </div>
                {% endif %}
            </div>

            <!-- Main Content -->
            <div class="col-md-9">
                <ul class="nav nav-tabs" id="mainTabs" role="tablist">
                    <li class="nav-item" role="presentation">
                        <button class="nav-link active" id="proxy-tab" data-bs-toggle="tab" data-bs-target="#proxy" type="button" role="tab">
                            <i class="fas fa-list"></i> HTTP History
                        </button>
                    </li>
                    <li class="nav-item" role="presentation">
                        <button class="nav-link" id="repeater-tab" data-bs-toggle="tab" data-bs-target="#repeater" type="button" role="tab">
                            <i class="fas fa-redo"></i> Repeater
                        </button>
                    </li>
                    <li class="nav-item" role="presentation">
                        <button class="nav-link" id="logs-tab" data-bs-toggle="tab" data-bs-target="#logs" type="button" role="tab">
                            <i class="fas fa-database"></i> Firebase Logs
                            {% if firebase_stats.queued_logs > 0 %}
                            <span class="badge bg-warning text-dark ms-1">{{ firebase_stats.queued_logs }}</span>
                            {% endif %}
                        </button>
                    </li>
                </ul>

                <div class="tab-content" id="mainTabContent">
                    <!-- HTTP History Tab -->
                    <div class="tab-pane fade show active" id="proxy" role="tabpanel">
                        <div class="card mt-3">
                            <div class="card-header">
                                <i class="fas fa-globe"></i> Intercepted Requests
                            </div>
                            <div class="card-body p-0">
                                <div class="table-responsive">
                                    <table class="table table-dark table-hover mb-0">
                                        <thead>
                                            <tr>
                                                <th>#</th>
                                                <th>Method</th>
                                                <th>URL</th>
                                                <th>Status</th>
                                                <th>Time</th>
                                                <th>Actions</th>
                                            </tr>
                                        </thead>
                                        <tbody id="request-table">
                                            {% for req in requests %}
                                            <tr onclick="selectRequest({{ req.id }})">
                                                <td>{{ req.id }}</td>
                                                <td><span class="method-{{ req.method.lower() }}">{{ req.method }}</span></td>
                                                <td class="text-truncate" style="max-width: 300px;">{{ req.url }}</td>
                                                <td>
                                                    {% if req.intercepted %}
                                                    <span class="status-intercepted">Intercepted</span>
                                                    {% else %}
                                                    <span class="status-forwarded">{{ req.status_code or 'Forwarded' }}</span>
                                                    {% endif %}
                                                </td>
                                                <td>{{ req.timestamp.split('T')[1].split('.')[0] if req.timestamp else '' }}</td>
                                                <td>
                                                    <button class="btn btn-sm btn-outline-primary" onclick="sendToRepeater({{ req.id }})">
                                                        <i class="fas fa-redo"></i>
                                                    </button>
                                                    <button class="btn btn-sm btn-outline-primary" onclick="copyUrl({{ req.id }})">
                                                        <i class="fas fa-copy"></i>
                                                    </button>
                                                </td>
                                            </tr>
                                            {% endfor %}
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        </div>

                        <!-- Request Details -->
                        <div class="card mt-3" id="request-details" style="display: none;">
                            <div class="card-header">
                                <i class="fas fa-info-circle"></i> Request Details
                            </div>
                            <div class="card-body">
                                <div id="request-content"></div>
                            </div>
                        </div>
                    </div>

                    <!-- Repeater Tab -->
                    <div class="tab-pane fade" id="repeater" role="tabpanel">
                        <div class="card mt-3">
                            <div class="card-header">
                                <i class="fas fa-redo"></i> Request Repeater
                            </div>
                            <div class="card-body">
                                <div class="row">
                                    <div class="col-md-6">
                                        <h6>Request</h6>
                                        <div class="mb-3">
                                            <select class="form-select" id="repeat-method">
                                                <option value="GET">GET</option>
                                                <option value="POST">POST</option>
                                                <option value="PUT">PUT</option>
                                                <option value="DELETE">DELETE</option>
                                            </select>
                                        </div>
                                        <div class="mb-3">
                                            <input type="url" class="form-control" id="repeat-url" placeholder="https://example.com/api/endpoint">
                                        </div>
                                        <div class="mb-3">
                                            <label class="form-label">Headers:</label>
                                            <textarea class="form-control" id="repeat-headers" rows="4" placeholder="Content-Type: application/json&#10;Authorization: Bearer token"></textarea>
                                        </div>
                                        <div class="mb-3">
                                            <label class="form-label">Body:</label>
                                            <textarea class="form-control" id="repeat-body" rows="6" placeholder="Request body content"></textarea>
                                        </div>
                                        <button class="btn btn-primary" onclick="sendRequest()">
                                            <i class="fas fa-paper-plane"></i> Send Request
                                        </button>
                                    </div>
                                    <div class="col-md-6">
                                        <h6>Response</h6>
                                        <div class="code-block" id="response-content" style="min-height: 400px;">
                                            Response will appear here...
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- Firebase Logs Tab -->
                    <div class="tab-pane fade" id="logs" role="tabpanel">
                        <div class="card mt-3">
                            <div class="card-header">
                                <i class="fas fa-database"></i> Firebase Cloud Logs
                                {% if firebase_stats.queued_logs > 0 %}
                                <span class="badge bg-warning text-dark ms-2">{{ firebase_stats.queued_logs }} Queued</span>
                                {% endif %}
                            </div>
                            <div class="card-body">
                                <div class="mb-3">
                                    <button class="btn btn-outline-primary me-2" onclick="refreshFirebaseLogs()">
                                        <i class="fas fa-sync"></i> Refresh Logs
                                    </button>
                                    <button class="btn btn-outline-primary" onclick="checkFirebaseStatus()">
                                        <i class="fas fa-database"></i> Check Connection
                                    </button>
                                </div>
                                <div id="firebase-logs">
                                    {% if firebase_stats.connected %}
                                    <p class="text-muted">Click "Refresh Logs" to load Firebase data...</p>
                                    {% else %}
                                    <div class="firebase-setup">
                                        <h6><i class="fas fa-exclamation-triangle"></i> Firebase Not Connected</h6>
                                        <p>Firebase logging is not available. Follow the setup instructions in the control panel to enable cloud logging.</p>
                                        {% if firebase_stats.queued_logs > 0 %}
                                        <p><strong>{{ firebase_stats.queued_logs }}</strong> logs are queued and will be uploaded once Firebase is connected.</p>
                                        {% endif %}
                                    </div>
                                    {% endif %}
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        let selectedRequestId = null;
        
        function toggleIntercept() {
            fetch('/api/toggle-intercept', { method: 'POST' })
                .then(response => response.json())
                .then(data => {
                    const status = document.getElementById('intercept-status');
                    if (data.enabled) {
                        status.innerHTML = '<span class="status-indicator status-running"></span>Enabled';
                    } else {
                        status.innerHTML = '<span class="status-indicator status-stopped"></span>Disabled';
                    }
                });
        }
        
        function clearLogs() {
            if (confirm('Clear all intercepted requests?')) {
                fetch('/api/clear-logs', { method: 'POST' })
                    .then(() => location.reload());
            }
        }
        
        function checkFirebaseStatus() {
            fetch('/api/firebase-status')
                .then(response => response.json())
                .then(data => {
                    const status = document.getElementById('firebase-status');
                    if (data.connected) {
                        status.innerHTML = '<span class="status-indicator status-running"></span>Connected';
                        if (data.queued_logs > 0) {
                            status.innerHTML += `<br><small class="text-muted">${data.queued_logs} queued</small>`;
                        }
                    } else {
                        status.innerHTML = '<span class="status-indicator status-warning"></span>Offline';
                        if (data.queued_logs > 0) {
                            status.innerHTML += `<br><small class="text-muted">${data.queued_logs} queued</small>`;
                        }
                    }
                });
        }
        
        function selectRequest(id) {
            selectedRequestId = id;
            fetch(`/api/request/${id}`)
                .then(response => response.json())
                .then(data => {
                    const details = document.getElementById('request-details');
                    const content = document.getElementById('request-content');
                    
                    content.innerHTML = `
                        <div class="row">
                            <div class="col-md-6">
                                <h6>Request</h6>
                                <div class="code-block">
                                    <strong>${data.method} ${data.url}</strong><br><br>
                                    <strong>Headers:</strong><br>
                                    ${Object.entries(data.headers).map(([k,v]) => `${k}: ${v}`).join('<br>')}
                                    <br><br>
                                    <strong>Body:</strong><br>
                                    ${data.body || '(empty)'}
                                </div>
                            </div>
                            <div class="col-md-6">
                                <h6>Response</h6>
                                <div class="code-block">
                                    <strong>Status:</strong> ${data.status_code || 'Pending'}<br><br>
                                    <strong>Headers:</strong><br>
                                    ${data.response_headers ? Object.entries(data.response_headers).map(([k,v]) => `${k}: ${v}`).join('<br>') : '(none)'}
                                    <br><br>
                                    <strong>Body:</strong><br>
                                    ${data.response_body || '(empty)'}
                                </div>
                            </div>
                        </div>
                    `;
                    
                    details.style.display = 'block';
                });
        }
        
        function sendToRepeater(id) {
            fetch(`/api/request/${id}`)
                .then(response => response.json())
                .then(data => {
                    document.getElementById('repeat-method').value = data.method;
                    document.getElementById('repeat-url').value = data.url;
                    document.getElementById('repeat-headers').value = 
                        Object.entries(data.headers).map(([k,v]) => `${k}: ${v}`).join('\\n');
                    document.getElementById('repeat-body').value = data.body || '';
                    
                    // Switch to repeater tab
                    document.getElementById('repeater-tab').click();
                });
        }
        
        function copyUrl(id) {
            fetch(`/api/request/${id}`)
                .then(response => response.json())
                .then(data => {
                    navigator.clipboard.writeText(data.url);
                    alert('URL copied to clipboard!');
                });
        }
        
        function sendRequest() {
            const method = document.getElementById('repeat-method').value;
            const url = document.getElementById('repeat-url').value;
            const headers = document.getElementById('repeat-headers').value;
            const body = document.getElementById('repeat-body').value;
            
            const responseDiv = document.getElementById('response-content');
            responseDiv.innerHTML = 'Sending request...';
            
            fetch('/api/send-request', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ method, url, headers, body })
            })
            .then(response => response.json())
            .then(data => {
                responseDiv.innerHTML = `
                    <strong>Status:</strong> ${data.status_code}<br><br>
                    <strong>Headers:</strong><br>
                    ${Object.entries(data.headers).map(([k,v]) => `${k}: ${v}`).join('<br>')}<br><br>
                    <strong>Body:</strong><br>
                    <pre>${data.body}</pre>
                `;
            })
            .catch(error => {
                responseDiv.innerHTML = `<span style="color: #dc3545;">Error: ${error.message}</span>`;
            });
        }
        
        function refreshFirebaseLogs() {
            const logsDiv = document.getElementById('firebase-logs');
            logsDiv.innerHTML = 'Loading Firebase logs...';
            
            fetch('/api/firebase-logs')
                .then(response => response.json())
                .then(data => {
                    if (data.logs && data.logs.length > 0) {
                        logsDiv.innerHTML = data.logs.map(log => `
                            <div class="card mb-2">
                                <div class="card-body">
                                    <div class="d-flex justify-content-between align-items-start">
                                        <div>
                                            <h6 class="method-${log.method.toLowerCase()}">${log.method} ${log.url}</h6>
                                            <small class="text-muted">${log.timestamp}</small>
                                        </div>
                                        <span class="badge ${log.status_code >= 200 && log.status_code < 300 ? 'bg-success' : log.status_code >= 400 ? 'bg-danger' : 'bg-warning'}">${log.status_code || 'N/A'}</span>
                                    </div>
                                    ${log.modified ? '<span class="badge bg-info mt-2">Modified</span>' : ''}
                                </div>
                            </div>
                        `).join('');
                    } else {
                        logsDiv.innerHTML = '<p class="text-muted">No Firebase logs available</p>';
                    }
                })
                .catch(error => {
                    logsDiv.innerHTML = `<p class="text-danger">Error loading logs: ${error.message}</p>`;
                });
        }
        
        // Auto-refresh request table and Firebase status every 3 seconds
        setInterval(() => {
            fetch('/api/requests')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('request-count').textContent = data.requests.length;
                });
            
            checkFirebaseStatus();
        }, 3000);
    </script>
</body>
</html>
"""

@app.route('/')
def index():
    firebase_stats = proxy_instance.get_firebase_stats()
    return render_template_string(HTML_TEMPLATE, 
                                proxy_port=PROXY_PORT,
                                request_count=len(proxy_instance.intercepted_requests),
                                requests=proxy_instance.intercepted_requests[-50:],
                                firebase_stats=firebase_stats)

@app.route('/api/requests')
def get_requests():
    return jsonify({'requests': proxy_instance.intercepted_requests})

@app.route('/api/request/<int:request_id>')
def get_request(request_id):
    for req in proxy_instance.intercepted_requests:
        if req['id'] == request_id:
            return jsonify(req)
    return jsonify({'error': 'Request not found'}), 404

@app.route('/api/toggle-intercept', methods=['POST'])
def toggle_intercept():
    proxy_instance.intercept_enabled = not proxy_instance.intercept_enabled
    return jsonify({'enabled': proxy_instance.intercept_enabled})

@app.route('/api/clear-logs', methods=['POST'])
def clear_logs():
    proxy_instance.intercepted_requests.clear()
    return jsonify({'success': True})

@app.route('/api/firebase-status')
def firebase_status():
    """Get current Firebase connection status"""
    return jsonify(proxy_instance.get_firebase_stats())

@app.route('/api/reconnect-firebase', methods=['POST'])
def reconnect_firebase():
    """Attempt to reconnect to Firebase"""
    success = proxy_instance.init_firebase()
    return jsonify({'success': success, 'stats': proxy_instance.get_firebase_stats()})

@app.route('/api/send-request', methods=['POST'])
def send_request():
    data = request.json
    try:
        # Parse headers
        headers = {}
        if data.get('headers'):
            for line in data['headers'].split('\n'):
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip()] = value.strip()
        
        # Make request
        response = requests.request(
            method=data['method'],
            url=data['url'],
            headers=headers,
            data=data.get('body', ''),
            timeout=10
        )
        
        return jsonify({
            'status_code': response.status_code,
            'headers': dict(response.headers),
            'body': response.text[:2000]  # Limit response size
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/firebase-logs')
def get_firebase_logs():
    if not proxy_instance.firebase_db:
        return jsonify({'logs': [], 'error': 'Firebase not connected'})
    
    try:
        docs = proxy_instance.firebase_db.collection('mitm_logs').order_by('timestamp', direction=firestore.Query.DESCENDING).limit(50).stream()
        logs = []
        for doc in docs:
            log_data = doc.to_dict()
            log_data['timestamp'] = log_data['timestamp'].isoformat() if log_data.get('timestamp') else ''
            logs.append(log_data)
        return jsonify({'logs': logs})
    except Exception as e:
        return jsonify({'logs': [], 'error': str(e)})

@app.route('/api/forward-request/<int:request_id>', methods=['POST'])
def forward_request(request_id):
    """Manually forward a pending request"""
    if request_id in proxy_instance.pending_requests:
        request_data = proxy_instance.pending_requests.pop(request_id)
        # Apply any modifications from the request
        modifications = request.json or {}
        if modifications:
            request_data = proxy_instance.modify_request(request_data, modifications)
        
        # Forward the request (this would be done in a separate thread in real implementation)
        return jsonify({'success': True, 'message': 'Request forwarded'})
    
    return jsonify({'error': 'Request not found'}), 404

@app.route('/api/drop-request/<int:request_id>', methods=['POST'])
def drop_request(request_id):
    """Drop a pending request"""
    if request_id in proxy_instance.pending_requests:
        proxy_instance.pending_requests.pop(request_id)
        return jsonify({'success': True, 'message': 'Request dropped'})
    
    return jsonify({'error': 'Request not found'}), 404

@app.route('/api/modify-request/<int:request_id>', methods=['POST'])
def modify_request(request_id):
    """Modify and forward a request"""
    modifications = request.json
    for req in proxy_instance.intercepted_requests:
        if req['id'] == request_id:
            modified_req = proxy_instance.modify_request(req.copy(), modifications)
            # In real implementation, this would forward the modified request
            return jsonify({'success': True, 'modified_request': modified_req})
    
    return jsonify({'error': 'Request not found'}), 404

def start_proxy_server():
    """Start the enhanced MITM proxy server"""
    def handler(*args, **kwargs):
        ProxyHandler(*args, proxy_instance=proxy_instance, **kwargs)
    
    # Use threading server for better performance
    server = ThreadingHTTPServer(('localhost', PROXY_PORT), handler)
    server.timeout = 1
    print(f"🔥 Enhanced MITM Proxy started on localhost:{PROXY_PORT}")
    print(f"📡 Supports HTTP/HTTPS tunneling and request modification")
    server.serve_forever()

def main():
    """Main function to start the application"""
    print("🚀 Starting CasioMITM - Security Analysis Tool")
    print("=" * 50)
    
    # Initialize Firebase
    proxy_instance.init_firebase()
    
    # Start proxy server in background thread
    proxy_thread = threading.Thread(target=start_proxy_server, daemon=True)
    proxy_thread.start()
    
    print(f"🌐 Web Interface: http://localhost:{WEB_PORT}")
    print(f"🔍 Proxy Server: localhost:{PROXY_PORT}")
    print("📋 Configure your browser to use the proxy for HTTP traffic")
    
    if proxy_instance.firebase_connected:
        print("🔥 Firebase Realtime Database logging enabled and connected")
        print(f"📊 Database: {FIREBASE_DATABASE_URL}")
    else:
        print("⚠ Firebase logging disabled - update FIREBASE_CONFIG with your credentials")
    
    print("=" * 50)
    
    # Start Flask web interface
    app.run(host='localhost', port=WEB_PORT, debug=False)

if __name__ == '__main__':
    main()
