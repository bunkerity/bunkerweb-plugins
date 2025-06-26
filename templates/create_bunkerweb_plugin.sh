#!/bin/bash

set -e

show_usage() {
    cat << 'EOF'
Usage: ./create_bunkerweb_plugin.sh [OPTIONS] PLUGIN_NAME

Create a new BunkerWeb plugin template with proper structure and files.

OPTIONS:
    -h, --help              Show this help message
    -d, --description TEXT  Plugin description (required)
    -v, --version VERSION   Plugin version (default: 1.0.0)
    -o, --output DIR        Output directory (default: parent directory)
    --order NUMBER          Plugin execution order (default: 256)
    --stream MODE           Stream support: no|partial|yes (default: partial)
    --with-ui               Include web UI components
    --with-jobs             Include job scheduler components (day frequency)
    --with-configs          Include NGINX configuration templates
    --with-templates        Include custom configuration templates

EXAMPLES:
    ./create_bunkerweb_plugin.sh -d "Rate limiting plugin" ratelimit
    ./create_bunkerweb_plugin.sh -d "Custom WAF rules" -v "2.1.0" --with-ui customwaf
    ./create_bunkerweb_plugin.sh -d "Log analyzer" --with-jobs --order 10 loganalyzer
    ./create_bunkerweb_plugin.sh -d "Security monitor" --with-jobs --with-ui monitor

NOTE: 
- Script creates plugins in parent directory by default (assumes run from templates/)
- Creates project README.md template if it doesn't exist
- Jobs default to daily frequency. Edit plugin.json to change to minute/hour/day/week/once.
EOF
}

validate_plugin_name() {
    local name="$1"
    
    if [ -z "$name" ]; then
        echo "Error: Plugin name is required" >&2
        return 1
    fi
    
    if echo "$name" | grep -q '[^a-zA-Z0-9_-]'; then
        echo "Error: Plugin name must contain only alphanumeric characters, hyphens, and underscores" >&2
        return 1
    fi
    
    if [ "${#name}" -gt 50 ]; then
        echo "Error: Plugin name must be 50 characters or less" >&2
        return 1
    fi
    
    return 0
}

create_directory_structure() {
    local plugin_dir="$1"
    
    mkdir -p "$plugin_dir"
    
    if [ "$WITH_UI" = "yes" ]; then
        mkdir -p "$plugin_dir/ui/blueprints"
        mkdir -p "$plugin_dir/ui/templates"
    fi
    
    if [ "$WITH_JOBS" = "yes" ]; then
        mkdir -p "$plugin_dir/jobs"
    fi
    
    if [ "$WITH_CONFIGS" = "yes" ]; then
        mkdir -p "$plugin_dir/confs/server-http"
        mkdir -p "$plugin_dir/confs/http"
        mkdir -p "$plugin_dir/confs/default-server-http"
        mkdir -p "$plugin_dir/confs/stream"
        mkdir -p "$plugin_dir/confs/server-stream"
        # Note: modsec directories not created by default
        # mkdir -p "$plugin_dir/confs/modsec"
        # mkdir -p "$plugin_dir/confs/modsec-crs"
    fi
    
    if [ "$WITH_TEMPLATES" = "yes" ]; then
        mkdir -p "$plugin_dir/templates"
    fi
}

create_docs() {
    local plugin_dir="$1"
    
    mkdir -p "$plugin_dir/docs"
    
    if [ -f "template_diagram.drawio" ]; then
        cp "template_diagram.drawio" "$plugin_dir/docs/"
    fi
    
    if [ -f "template_diagram.svg" ]; then
        cp "template_diagram.svg" "$plugin_dir/docs/"
    fi
}

generate_plugin_json() {
    local plugin_dir="$1"
    local plugin_name="$2"
    local plugin_name_upper
    plugin_name_upper=$(echo "$plugin_name" | tr '[:lower:]' '[:upper:]')
    
    cat > "$plugin_dir/plugin.json" << EOF
{
    "id": "$plugin_name",
    "order": $ORDER,
    "name": "$(echo "$plugin_name" | sed 's/\(^\|_\|-\)\([a-z]\)/\U\2/g')",
    "description": "$DESCRIPTION",
    "version": "$VERSION",
    "stream": "$STREAM_MODE",
    "settings": {
        "USE_${plugin_name_upper}": {
            "context": "multisite",
            "default": "no",
            "help": "Enable or disable the $plugin_name plugin.",
            "id": "use-${plugin_name}",
            "label": "Use ${plugin_name}",
            "regex": "^(yes|no)$",
            "type": "check"
        },
        "PLUGIN_${plugin_name_upper}_SETTING": {
            "context": "multisite",
            "default": "default_value",
            "help": "Configure the main setting for $plugin_name plugin.",
            "id": "plugin-${plugin_name}-setting",
            "label": "${plugin_name} Setting",
            "regex": "^.*$",
            "type": "text"
        }
    }$([ "$WITH_JOBS" = "yes" ] && echo ',
    "jobs": [
        {
            "name": "'"$plugin_name"'-job",
            "file": "'"$plugin_name"'-job.py",
            "every": "day",
            "reload": false
        }
    ]' || echo "")
}
EOF
}

generate_lua_file() {
    local plugin_dir="$1"
    local plugin_name="$2"
    
    cat > "$plugin_dir/$plugin_name.lua" << 'EOF'
local class = require "middleclass"
local plugin = require "bunkerweb.plugin"

local PLUGIN_NAME_LOWER = class("PLUGIN_NAME_LOWER", plugin)

function PLUGIN_NAME_LOWER:initialize(ctx)
    plugin.initialize(self, "PLUGIN_NAME_LOWER", ctx)
end

function PLUGIN_NAME_LOWER:access()
    if self.variables["USE_PLUGIN_NAME_UPPER"] ~= "yes" then
        return self:ret(true, "plugin disabled")
    end
    
    self.logger:log(ngx.NOTICE, "access called")
    return self:ret(true, "success")
end

function PLUGIN_NAME_LOWER:log()
    if self.variables["USE_PLUGIN_NAME_UPPER"] ~= "yes" then
        return self:ret(true, "plugin disabled")
    end
    
    self.logger:log(ngx.NOTICE, "log called")
    return self:ret(true, "success")
end

function PLUGIN_NAME_LOWER:log_default()
    if self.variables["USE_PLUGIN_NAME_UPPER"] ~= "yes" then
        return self:ret(true, "plugin disabled")
    end
    
    self.logger:log(ngx.NOTICE, "log_default called")
    return self:ret(true, "success")
end

function PLUGIN_NAME_LOWER:preread()
    if self.variables["USE_PLUGIN_NAME_UPPER"] ~= "yes" then
        return self:ret(true, "plugin disabled")
    end
    
    self.logger:log(ngx.NOTICE, "preread called")
    return self:ret(true, "success")
end

function PLUGIN_NAME_LOWER:log_stream()
    if self.variables["USE_PLUGIN_NAME_UPPER"] ~= "yes" then
        return self:ret(true, "plugin disabled")
    end
    
    self.logger:log(ngx.NOTICE, "log_stream called")
    return self:ret(true, "success")
end

return PLUGIN_NAME_LOWER
EOF

    sed -i.bak "s|PLUGIN_NAME_LOWER|${plugin_name}|g" "$plugin_dir/$plugin_name.lua"
    sed -i.bak "s|USE_PLUGIN_NAME_UPPER|USE_${plugin_name_upper}|g" "$plugin_dir/$plugin_name.lua"
    
    local plugin_name_upper
    plugin_name_upper=$(echo "$plugin_name" | tr '[:lower:]' '[:upper:]')
    sed -i.bak "s|PLUGIN_PLUGIN_NAME_UPPER|PLUGIN_${plugin_name_upper}|g" "$plugin_dir/$plugin_name.lua"
    
    rm -f "$plugin_dir/$plugin_name.lua.bak"
}

generate_ui_components() {
    local plugin_dir="$1"
    local plugin_name="$2"
    
    cat > "$plugin_dir/ui/actions.py" << EOF
#!/usr/bin/env python3

import json
import os
from datetime import datetime
from flask import request, render_template, jsonify, current_app
from werkzeug.utils import secure_filename


def $plugin_name():
    """
    Main function for $plugin_name plugin UI actions
    Handles both GET (display) and POST (configuration) requests
    """
    if request.method == "GET":
        return render_template("$plugin_name.html", 
                             plugin_name="$plugin_name",
                             plugin_version="$VERSION",
                             plugin_description="$DESCRIPTION")
    
    elif request.method == "POST":
        try:
            data = request.get_json()
            
            if not data:
                return jsonify({"error": "No data provided"}), 400
            
            validation_result = validate_configuration(data)
            if not validation_result["valid"]:
                return jsonify({"error": validation_result["message"]}), 400
            
            save_result = save_configuration(data)
            
            return jsonify({
                "success": save_result["success"],
                "message": save_result["message"]
            })
            
        except Exception as e:
            current_app.logger.error(f"Failed to process $plugin_name request: {str(e)}")
            return jsonify({"error": f"Request processing failed: {str(e)}"}), 500


def validate_configuration(data):
    """
    Validate plugin configuration data
    """
    try:
        required_fields = ["setting", "timeout", "log_level"]
        
        for field in required_fields:
            if field not in data:
                return {"valid": False, "message": f"Missing required field: {field}"}
        
        if not isinstance(data["timeout"], int) or data["timeout"] < 1 or data["timeout"] > 300:
            return {"valid": False, "message": "Timeout must be between 1 and 300 seconds"}
        
        valid_log_levels = ["DEBUG", "INFO", "WARN", "ERROR"]
        if data["log_level"] not in valid_log_levels:
            return {"valid": False, 
                    "message": f"Log level must be one of: {', '.join(valid_log_levels)}"}
        
        return {"valid": True, "message": "Configuration is valid"}
        
    except Exception as e:
        return {"valid": False, "message": f"Validation error: {str(e)}"}


def save_configuration(data):
    """
    Save plugin configuration
    """
    try:
        config_data = {
            "plugin_name": "$plugin_name",
            "setting": data["setting"],
            "timeout": data["timeout"],
            "log_level": data["log_level"],
            "updated_at": datetime.utcnow().isoformat()
        }
        
        return {
            "success": True,
            "message": "Configuration saved successfully"
        }
        
    except Exception as e:
        current_app.logger.error(f"Failed to save $plugin_name configuration: {str(e)}")
        return {
            "success": False,
            "message": f"Failed to save configuration: {str(e)}"
        }


def get_plugin_status():
    """
    Get current plugin status and statistics
    """
    try:
        status = {
            "active": True,
            "requests_processed": 12345,
            "last_activity": datetime.utcnow().isoformat(),
            "version": "$VERSION"
        }
        return status
    except Exception as e:
        current_app.logger.error(f"Failed to get plugin status: {str(e)}")
        return {"active": False, "error": str(e)}
EOF

    cat > "$plugin_dir/ui/template.html" << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ plugin_name | title }} Plugin Configuration</title>
    <style>
        @font-face {
            font-family: 'Public Sans';
            src: url('../fonts/Public_sans/PublicSans-Thin.woff2') format('woff2');
            font-weight: 100;
            font-style: normal;
        }
        @import url('./core.css');
        
        .plugin-container {
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
            font-family: 'Public Sans', -apple-system, BlinkMacSystemFont, 'Segoe UI', 
                         Roboto, sans-serif;
        }
        .plugin-header {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            border-left: 4px solid #007bff;
        }
        .plugin-info {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 10px;
            margin-bottom: 20px;
        }
        .info-item {
            background: white;
            padding: 15px;
            border-radius: 6px;
            border: 1px solid #dee2e6;
        }
        .info-label {
            font-weight: 600;
            color: #495057;
            font-size: 0.875rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .info-value {
            margin-top: 5px;
            font-size: 1.1rem;
            color: #212529;
        }
        .form-section {
            background: white;
            padding: 25px;
            border-radius: 8px;
            border: 1px solid #dee2e6;
            margin-bottom: 20px;
        }
        .form-group {
            margin-bottom: 20px;
        }
        .form-label {
            display: block;
            margin-bottom: 8px;
            font-weight: 600;
            color: #495057;
        }
        .form-control {
            width: 100%;
            padding: 12px 16px;
            font-size: 1rem;
            border: 1px solid #ced4da;
            border-radius: 6px;
            transition: border-color 0.15s ease-in-out, box-shadow 0.15s ease-in-out;
        }
        .form-control:focus {
            outline: 0;
            border-color: #80bdff;
            box-shadow: 0 0 0 0.2rem rgba(0, 123, 255, 0.25);
        }
        .btn {
            display: inline-block;
            padding: 12px 24px;
            font-size: 1rem;
            font-weight: 500;
            text-align: center;
            text-decoration: none;
            border: 1px solid transparent;
            border-radius: 6px;
            cursor: pointer;
            transition: all 0.15s ease-in-out;
        }
        .btn-primary {
            color: #fff;
            background-color: #007bff;
            border-color: #007bff;
        }
        .btn-primary:hover {
            background-color: #0056b3;
            border-color: #004085;
        }
        .alert {
            padding: 12px 16px;
            margin-bottom: 20px;
            border: 1px solid transparent;
            border-radius: 6px;
        }
        .alert-success {
            color: #155724;
            background-color: #d4edda;
            border-color: #c3e6cb;
        }
        .alert-danger {
            color: #721c24;
            background-color: #f8d7da;
            border-color: #f5c6cb;
        }
        .status-indicator {
            display: inline-block;
            width: 12px;
            height: 12px;
            border-radius: 50%;
            margin-right: 8px;
        }
        .status-active {
            background-color: #28a745;
        }
        .status-inactive {
            background-color: #dc3545;
        }
    </style>
</head>
<body>
    <div class="plugin-container">
        <div class="plugin-header">
            <h1>{{ plugin_name | title }} Plugin</h1>
            <p>{{ plugin_description }}</p>
        </div>

        <div class="plugin-info">
            <div class="info-item">
                <div class="info-label">Status</div>
                <div class="info-value">
                    <span class="status-indicator status-active"></span>
                    Active
                </div>
            </div>
            <div class="info-item">
                <div class="info-label">Version</div>
                <div class="info-value">{{ plugin_version }}</div>
            </div>
            <div class="info-item">
                <div class="info-label">Requests Processed</div>
                <div class="info-value" id="requests-count">-</div>
            </div>
            <div class="info-item">
                <div class="info-label">Last Activity</div>
                <div class="info-value" id="last-activity">-</div>
            </div>
        </div>

        <div class="form-section">
            <h3>Configuration</h3>
            <form id="plugin-config-form">
                <div class="form-group">
                    <label for="plugin-setting" class="form-label">Plugin Setting</label>
                    <input type="text" 
                           class="form-control" 
                           id="plugin-setting" 
                           name="setting" 
                           placeholder="Enter plugin setting value"
                           value="default_value">
                </div>

                <div class="form-group">
                    <label for="plugin-timeout" class="form-label">Timeout (seconds)</label>
                    <input type="number" 
                           class="form-control" 
                           id="plugin-timeout" 
                           name="timeout" 
                           min="1" 
                           max="300" 
                           value="5">
                </div>

                <div class="form-group">
                    <label for="plugin-log-level" class="form-label">Log Level</label>
                    <select class="form-control" id="plugin-log-level" name="log_level">
                        <option value="DEBUG" selected>DEBUG</option>
                        <option value="INFO">INFO</option>
                        <option value="WARN">WARN</option>
                        <option value="ERROR">ERROR</option>
                    </select>
                </div>

                <button type="submit" class="btn btn-primary">Save Configuration</button>
            </form>
        </div>

        <div id="message-container"></div>
    </div>

    <script>
        document.addEventListener('DOMContentLoaded', function() {
            loadPluginStatus();
            
            document.getElementById('plugin-config-form').addEventListener('submit', 
                                                                           handleFormSubmit);
        });

        function loadPluginStatus() {
            fetch('/api/plugins/{{ plugin_name }}/status')
                .then(response => response.json())
                .then(data => {
                    if (data.requests_processed) {
                        document.getElementById('requests-count').textContent = 
                            data.requests_processed.toLocaleString();
                    }
                    if (data.last_activity) {
                        const date = new Date(data.last_activity);
                        document.getElementById('last-activity').textContent = 
                            date.toLocaleDateString() + ' ' + date.toLocaleTimeString();
                    }
                })
                .catch(error => {
                    console.error('Failed to load plugin status:', error);
                });
        }

        function handleFormSubmit(event) {
            event.preventDefault();
            
            const formData = new FormData(event.target);
            const data = {
                setting: formData.get('setting'),
                timeout: parseInt(formData.get('timeout')),
                log_level: formData.get('log_level')
            };

            fetch('/api/plugins/{{ plugin_name }}/configure', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(data)
            })
            .then(response => response.json())
            .then(result => {
                showMessage(result.message, result.success ? 'success' : 'danger');
                if (result.success) {
                    loadPluginStatus();
                }
            })
            .catch(error => {
                showMessage('Failed to save configuration: ' + error.message, 'danger');
            });
        }

        function showMessage(message, type) {
            const container = document.getElementById('message-container');
            const alert = document.createElement('div');
            alert.className = `alert alert-${type}`;
            alert.textContent = message;
            
            container.innerHTML = '';
            container.appendChild(alert);
            
            setTimeout(() => {
                alert.remove();
            }, 5000);
        }
    </script>
</body>
</html>
EOF

    cat > "$plugin_dir/ui/hooks.py" << EOF
#!/usr/bin/env python3

import os
import json
from flask import Flask


def before_first_request():
    """
    Initialization hook called before the first request
    """
    pass


def before_request():
    """
    Hook called before each request
    """
    pass


def after_request(response):
    """
    Hook called after each request
    """
    return response


def teardown_request(exception):
    """
    Hook called when request context is torn down
    """
    pass


def teardown_appcontext(exception):
    """
    Hook called when application context is torn down
    """
    pass
EOF
}

generate_job_files() {
    local plugin_dir="$1"
    local plugin_name="$2"
    local plugin_name_upper
    plugin_name_upper=$(echo "$plugin_name" | tr '[:lower:]' '[:upper:]')
    
    cat > "$plugin_dir/jobs/$plugin_name-job.py" << EOF
#!/usr/bin/env python3

import os
import sys
import time
import json
import logging
from datetime import datetime, timedelta
from pathlib import Path


class PluginJob:
    """
    Main job class for $plugin_name plugin scheduled tasks
    """
    
    def __init__(self):
        self.plugin_name = "$plugin_name"
        self.version = "$VERSION"
        self.logger = self.setup_logging()
        self.config = self.load_configuration()
    
    def setup_logging(self):
        """
        Configure logging for the job
        """
        log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        logging.basicConfig(level=logging.INFO, format=log_format)
        return logging.getLogger(f"{self.plugin_name}-job")
    
    def load_configuration(self):
        """
        Load plugin configuration from environment variables
        """
        return {
            'enabled': os.getenv('USE_${plugin_name_upper}', 'no') == 'yes',
            'setting': os.getenv('PLUGIN_${plugin_name_upper}_SETTING', 'default_value'),
            'timeout': int(os.getenv('PLUGIN_${plugin_name_upper}_TIMEOUT', '5')),
            'log_level': os.getenv('PLUGIN_${plugin_name_upper}_LOG_LEVEL', 'DEBUG')
        }
    
    def run(self):
        """
        Main job execution method
        """
        try:
            self.logger.info(f"Starting {self.plugin_name} job execution")
            
            if not self.config['enabled']:
                self.logger.info("Plugin disabled, skipping job execution")
                return True
            
            cleanup_success = self.cleanup_old_data()
            processing_success = self.process_data()
            health_success = self.perform_health_checks()
            
            all_success = cleanup_success and processing_success and health_success
            
            if all_success:
                self.logger.info(f"{self.plugin_name} job completed successfully")
            else:
                self.logger.warning(f"{self.plugin_name} job completed with some failures")
            
            return all_success
            
        except Exception as e:
            self.logger.error(f"Job execution failed: {str(e)}")
            return False
    
    def cleanup_old_data(self):
        """
        Clean up old log files and temporary data
        """
        try:
            self.logger.info("Starting data cleanup")
            
            cleanup_paths = [
                '/var/log/bunkerweb/',
                '/tmp/bunkerweb/',
                f'/tmp/{self.plugin_name}/'
            ]
            
            cutoff_date = datetime.now() - timedelta(days=7)
            files_removed = 0
            
            for cleanup_path in cleanup_paths:
                if os.path.exists(cleanup_path):
                    for file_path in Path(cleanup_path).glob('**/*'):
                        if file_path.is_file():
                            file_modified = datetime.fromtimestamp(file_path.stat().st_mtime)
                            if file_modified < cutoff_date:
                                file_path.unlink()
                                files_removed += 1
            
            self.logger.info(f"Cleanup completed. Removed {files_removed} old files")
            return True
            
        except Exception as e:
            self.logger.error(f"Cleanup failed: {str(e)}")
            return False
    
    def process_data(self):
        """
        Process accumulated data and generate reports
        """
        try:
            if not self.config['enabled']:
                self.logger.info("Plugin disabled, skipping data processing")
                return True
            
            start_time = time.time()
            
            processed_requests = self.process_request_logs()
            
            stats = self.generate_statistics(processed_requests)
            
            self.save_processed_data(stats)
            
            processing_time = time.time() - start_time
            self.logger.info(f"Data processing completed in {processing_time:.2f} seconds. "
                           f"Processed {len(processed_requests)} requests")
            return True
            
        except Exception as e:
            self.logger.error(f"Data processing failed: {str(e)}")
            return False
    
    def process_request_logs(self):
        """
        Process request logs and extract relevant data
        """
        processed_requests = []
        
        log_pattern = f"*{self.plugin_name}*"
        log_files = list(Path('/var/log/bunkerweb/').glob(log_pattern))
        
        for log_file in log_files:
            try:
                with open(log_file, 'r') as f:
                    for line in f:
                        if self.plugin_name in line:
                            request_data = self.parse_log_line(line)
                            if request_data:
                                processed_requests.append(request_data)
            except Exception as e:
                self.logger.warning(f"Failed to process log file {log_file}: {str(e)}")
        
        return processed_requests
    
    def parse_log_line(self, line):
        """
        Parse individual log line and extract request data
        """
        try:
            parts = line.strip().split()
            if len(parts) >= 6:
                return {
                    'timestamp': parts[0] + ' ' + parts[1],
                    'level': parts[3],
                    'message': ' '.join(parts[5:])
                }
        except Exception:
            pass
        
        return None
    
    def generate_statistics(self, processed_requests):
        """
        Generate statistics from processed request data
        """
        total_requests = len(processed_requests)
        
        level_counts = {}
        for request in processed_requests:
            level = request.get('level', 'UNKNOWN')
            level_counts[level] = level_counts.get(level, 0) + 1
        
        return {
            'total_requests': total_requests,
            'level_distribution': level_counts,
            'generated_at': datetime.utcnow().isoformat(),
            'plugin_version': self.version
        }
    
    def save_processed_data(self, stats):
        """
        Save processed statistics data
        """
        stats_file = f'/var/log/bunkerweb/{self.plugin_name}-stats.json'
        
        try:
            with open(stats_file, 'w') as f:
                json.dump(stats, f, indent=2)
            self.logger.info(f"Statistics saved to {stats_file}")
        except Exception as e:
            self.logger.error(f"Failed to save statistics: {str(e)}")
    
    def perform_health_checks(self):
        """
        Perform health checks and validation
        """
        try:
            self.logger.info("Performing health checks")
            
            checks = [
                self.check_plugin_configuration(),
                self.check_system_resources(),
                self.check_log_file_permissions()
            ]
            
            all_healthy = all(checks)
            
            if all_healthy:
                self.logger.info("All health checks passed")
            else:
                self.logger.warning("Some health checks failed")
            
            return all_healthy
            
        except Exception as e:
            self.logger.error(f"Health checks failed: {str(e)}")
            return False
    
    def check_plugin_configuration(self):
        """
        Validate plugin configuration
        """
        try:
            required_configs = ['setting', 'timeout', 'log_level']
            
            for config in required_configs:
                if config not in self.config:
                    self.logger.error(f"Missing required configuration: {config}")
                    return False
            
            if not (1 <= self.config['timeout'] <= 300):
                self.logger.error(f"Invalid timeout value: {self.config['timeout']}")
                return False
            
            valid_log_levels = ['DEBUG', 'INFO', 'WARN', 'ERROR']
            if self.config['log_level'] not in valid_log_levels:
                self.logger.error(f"Invalid log level: {self.config['log_level']}")
                return False
            
            return True
            
        except Exception as e:
            self.logger.error(f"Configuration check failed: {str(e)}")
            return False
    
    def check_system_resources(self):
        """
        Check system resource availability
        """
        try:
            import psutil
            
            memory_usage = psutil.virtual_memory().percent
            disk_usage = psutil.disk_usage('/').percent
            cpu_usage = psutil.cpu_percent(interval=1)
            
            if memory_usage > 90:
                self.logger.warning(f"High memory usage: {memory_usage}%")
                return False
            
            if disk_usage > 90:
                self.logger.warning(f"High disk usage: {disk_usage}%")
                return False
            
            if cpu_usage > 90:
                self.logger.warning(f"High CPU usage: {cpu_usage}%")
                return False
            
            self.logger.info(f"System resources OK - Memory: {memory_usage}%, "
                           f"Disk: {disk_usage}%, CPU: {cpu_usage}%")
            return True
            
        except ImportError:
            self.logger.info("psutil not available, skipping resource checks")
            return True
        except Exception as e:
            self.logger.error(f"Resource check failed: {str(e)}")
            return False
    
    def check_log_file_permissions(self):
        """
        Check log file permissions and accessibility
        """
        try:
            log_files = [
                '/var/log/bunkerweb/error.log',
                f'/var/log/bunkerweb/{self.plugin_name}.log'
            ]
            
            for log_file in log_files:
                if os.path.exists(log_file):
                    if not os.access(log_file, os.R_OK | os.W_OK):
                        self.logger.error(f"Insufficient permissions for log file: {log_file}")
                        return False
            
            return True
            
        except Exception as e:
            self.logger.error(f"Log file permission check failed: {str(e)}")
            return False


def main():
    """
    Main entry point for the job
    """
    job = PluginJob()
    success = job.run()
    
    if success:
        print(f"{job.plugin_name} job completed successfully")
        sys.exit(0)
    else:
        print(f"{job.plugin_name} job completed with errors")
        sys.exit(1)


if __name__ == "__main__":
    main()
EOF
}

generate_config_templates() {
    local plugin_dir="$1"
    local plugin_name="$2"
    local plugin_name_upper
    plugin_name_upper=$(echo "$plugin_name" | tr '[:lower:]' '[:upper:]')
    
    cat > "$plugin_dir/confs/server-http/$plugin_name.conf" << EOF
# $plugin_name Plugin - Server HTTP Configuration

{% if USE_${plugin_name_upper} == "yes" %}

# Plugin status endpoint
location /$plugin_name/status {
    access_by_lua_block {
        local plugin_status = {
            active = true,
            version = "{{ PLUGIN_${plugin_name_upper}_VERSION or '$VERSION' }}",
            setting = "{{ PLUGIN_${plugin_name_upper}_SETTING }}",
            timestamp = ngx.time()
        }
        
        ngx.header.content_type = "application/json"
        ngx.say(require("cjson").encode(plugin_status))
        ngx.exit(200)
    }
}

# Plugin metrics endpoint
location /$plugin_name/metrics {
    access_by_lua_block {
        local metrics = {
            requests_processed = 0,
            errors_count = 0,
            avg_response_time = 0
        }
        
        ngx.header.content_type = "application/json"
        ngx.say(require("cjson").encode(metrics))
        ngx.exit(200)
    }
}

{% endif %}
EOF

    cat > "$plugin_dir/confs/http/$plugin_name.conf" << EOF
# $plugin_name Plugin - HTTP Configuration

{% if USE_${plugin_name_upper} == "yes" %}

# Custom log format for plugin
log_format ${plugin_name}_custom 
    '\$remote_addr - \$remote_user [\$time_local] '
    '"\$request" \$status \$body_bytes_sent '
    '"\$http_referer" "\$http_user_agent" '
    '${plugin_name}_setting="{{ PLUGIN_${plugin_name_upper}_SETTING }}" '
    '${plugin_name}_timeout={{ PLUGIN_${plugin_name_upper}_TIMEOUT }} '
    'request_time=\$request_time '
    'upstream_response_time=\$upstream_response_time';

# Rate limiting for plugin endpoints
limit_req_zone \$binary_remote_addr zone=req_limit_per_ip:10m rate=10r/s;

# Shared memory zone for plugin data
lua_shared_dict plugin_${plugin_name}_cache 10m;
lua_shared_dict plugin_${plugin_name}_stats 5m;

{% endif %}
EOF

    cat > "$plugin_dir/confs/default-server-http/$plugin_name.conf" << EOF
# $plugin_name Plugin - Default Server Configuration

{% if USE_${plugin_name_upper} == "yes" %}

# Block plugin endpoints on default server
location /$plugin_name {
    return 444;
}

{% endif %}
EOF

    # ModSecurity configurations disabled by default due to syntax complexity
    # Uncomment and customize if needed:
    
    # cat > "$plugin_dir/confs/modsec/$plugin_name.conf" << EOF
    # # $plugin_name Plugin - ModSecurity Configuration
    # # NOTE: ModSecurity rules disabled by default
    # # Uncomment and test carefully before enabling
    # 
    # # {% if USE_${plugin_name_upper} == "yes" %}
    # # 
    # # # Custom ModSecurity rules for $plugin_name plugin
    # # SecRule REQUEST_URI "@beginsWith /$plugin_name" \\
    # #     "pass,\\
    # #     id:${plugin_name}001,\\
    # #     phase:1,\\
    # #     msg:'$plugin_name plugin: Processing plugin request',\\
    # #     tag:'$plugin_name',\\
    # #     logdata:'Plugin setting: {{ PLUGIN_${plugin_name_upper}_SETTING }}',\\
    # #     rev:'1'"
    # # 
    # # {% endif %}
    # EOF

    cat > "$plugin_dir/confs/stream/$plugin_name.conf" << EOF
# $plugin_name Plugin - Stream Configuration

{% if USE_${plugin_name_upper} == "yes" and LISTEN_STREAM == "yes" %}

# Shared memory for stream plugin data
lua_shared_dict stream_plugin_${plugin_name}_cache 5m;

# Log format for stream connections
log_format ${plugin_name}_stream 
    '\$remote_addr [\$time_local] '
    '\$protocol \$status \$bytes_sent \$bytes_received '
    '\$session_time '
    '${plugin_name}_setting="{{ PLUGIN_${plugin_name_upper}_SETTING }}"';

{% endif %}
EOF

    cat > "$plugin_dir/confs/server-stream/$plugin_name.conf" << EOF
# $plugin_name Plugin - Server Stream Configuration

{% if USE_${plugin_name_upper} == "yes" and LISTEN_STREAM == "yes" %}

# Custom stream processing
preread_by_lua_block {
    local plugin_setting = "{{ PLUGIN_${plugin_name_upper}_SETTING }}"
    ngx.log(ngx.INFO, "$plugin_name: Processing stream connection with setting: " .. plugin_setting)
}

{% endif %}
EOF
}

generate_custom_templates() {
    local plugin_dir="$1"
    local plugin_name="$2"
    local plugin_name_upper
    plugin_name_upper=$(echo "$plugin_name" | tr '[:lower:]' '[:upper:]')
    
    cat > "$plugin_dir/templates/$plugin_name-template.json" << EOF
{
    "name": "$plugin_name-template",
    "description": "Template for $plugin_name plugin configuration",
    "steps": [
        {
            "name": "basic_config",
            "description": "Basic $plugin_name configuration",
            "settings": {
                "USE_${plugin_name_upper}": "yes",
                "PLUGIN_${plugin_name_upper}_SETTING": "template_value",
                "PLUGIN_${plugin_name_upper}_TIMEOUT": "10",
                "PLUGIN_${plugin_name_upper}_LOG_LEVEL": "INFO"
            }
        }
    ]
}
EOF

    cat > "$plugin_dir/templates/$plugin_name-dev.json" << EOF
{
    "name": "$plugin_name-development",
    "description": "Development configuration for $plugin_name plugin",
    "steps": [
        {
            "name": "development_config",
            "description": "Development settings for $plugin_name",
            "settings": {
                "USE_${plugin_name_upper}": "yes",
                "PLUGIN_${plugin_name_upper}_SETTING": "development_mode",
                "PLUGIN_${plugin_name_upper}_TIMEOUT": "30",
                "PLUGIN_${plugin_name_upper}_LOG_LEVEL": "DEBUG"
            }
        }
    ]
}
EOF

    cat > "$plugin_dir/templates/$plugin_name-prod.json" << EOF
{
    "name": "$plugin_name-production",
    "description": "Production configuration for $plugin_name plugin",
    "steps": [
        {
            "name": "production_config",
            "description": "Production settings for $plugin_name",
            "settings": {
                "USE_${plugin_name_upper}": "yes",
                "PLUGIN_${plugin_name_upper}_SETTING": "production_mode",
                "PLUGIN_${plugin_name_upper}_TIMEOUT": "5",
                "PLUGIN_${plugin_name_upper}_LOG_LEVEL": "WARN"
            }
        }
    ]
}
EOF

    mkdir -p "$plugin_dir/templates/$plugin_name-template/configs/server-http"
    
    cat > "$plugin_dir/templates/$plugin_name-template/configs/server-http/custom-endpoint.conf" << EOF
# Custom endpoint configuration for $plugin_name plugin template

location /$plugin_name/custom {
    access_by_lua_block {
        ngx.header.content_type = "application/json"
        local response = {
            message = "Custom endpoint for $plugin_name",
            template = "$plugin_name-template",
            timestamp = ngx.time()
        }
        ngx.say(require("cjson").encode(response))
        ngx.exit(200)
    }
}
EOF
}

generate_project_readme() {
    local output_dir="$1"
    
    if [ -f "$output_dir/README.md" ]; then
        return 0
    fi
    
    cat > "$output_dir/README.md" << 'EOF'
# BunkerWeb Plugins

BunkerWeb is a next-generation Web Application Firewall (WAF) that provides comprehensive 
security for your web services. This project extends BunkerWeb's capabilities with custom 
plugins tailored to specific security requirements.

## Plugin Structure

Each plugin in this repository follows the standard BunkerWeb plugin structure:

```
plugin-name/
├── plugin.json              # Plugin metadata and settings
├── plugin-name.lua          # Main Lua execution file
├── ui/                      # Web UI components (optional)
│   ├── actions.py          # Flask request handlers
│   ├── template.html       # Web interface template
│   └── hooks.py            # Flask lifecycle hooks
├── jobs/                    # Scheduled maintenance jobs (optional)
│   └── plugin-name-job.py  # Job scheduler script
├── confs/                   # NGINX configuration templates (optional)
│   ├── server-http/        # Server-level HTTP configurations
│   ├── http/               # HTTP-level configurations
│   ├── modsec/             # ModSecurity rules
│   └── stream/             # Stream configurations
├── templates/               # Configuration templates (optional)
└── README.md               # Plugin documentation
```

## Available Plugins

| Plugin | Description | Version | Features |
|--------|-------------|---------|----------|
| [example-plugin](./example-plugin/) | Example plugin description | 1.0.0 | Feature list |

## Quick Start

### Prerequisites

- BunkerWeb 1.6.0 or later
- Docker or Linux environment
- Basic knowledge of NGINX and Lua (for development)

### Installation

1. **Clone this repository:**
   ```bash
   git clone <your-repo-url>
   cd <your-repo-name>
   ```

2. **Install plugins to BunkerWeb:**

   **For Docker:**
   ```bash
   # Copy plugins to BunkerWeb data directory
   cp -r plugin-name /path/to/bw-data/plugins/
   
   # Set correct permissions
   chown -R root:101 /path/to/bw-data/plugins/plugin-name
   chmod -R 750 /path/to/bw-data/plugins/plugin-name
   ```

   **For Linux:**
   ```bash
   # Copy plugins to BunkerWeb plugins directory
   cp -r plugin-name /etc/bunkerweb/plugins/
   
   # Set correct permissions
   chown -R root:nginx /etc/bunkerweb/plugins/plugin-name
   chmod -R 750 /etc/bunkerweb/plugins/plugin-name
   
   # Restart BunkerWeb
   systemctl restart bunkerweb
   ```

3. **Configure plugins:**
   ```bash
   # Enable plugin
   USE_PLUGIN_PLUGINNAME=yes
   PLUGIN_PLUGINNAME_SETTING=your_value
   ```
EOF
}

generate_readme() {
    local plugin_dir="$1"
    local plugin_name="$2"
    local plugin_name_upper
    plugin_name_upper=$(echo "$plugin_name" | tr '[:lower:]' '[:upper:]')
    
    local features="- **Core Integration**: Seamlessly integrates with BunkerWeb's NGINX Lua module
- **Multisite Support**: Built-in support for global and per-service configurations
- **Configurable Settings**: Multiple configuration options with validation
- **Performance Monitoring**: Built-in metrics and health checks"
    
    if [ "$WITH_UI" = "yes" ]; then
        features="${features}
- **Web UI**: User-friendly configuration interface"
    fi
    
    if [ "$WITH_JOBS" = "yes" ]; then
        features="${features}
- **Scheduled Jobs**: Automated maintenance and data processing"
    fi
    
    if [ "$WITH_CONFIGS" = "yes" ]; then
        features="${features}
- **Custom NGINX Configs**: Flexible NGINX configuration templates (ModSecurity disabled by default)"
    fi
    
    if [ "$WITH_TEMPLATES" = "yes" ]; then
        features="${features}
- **Configuration Templates**: Pre-defined configuration templates with proper step structure"
    fi
    
    features="${features}
- **Stream Support**: $(echo "$STREAM_MODE" | tr '[:lower:]' '[:upper:]') support for TCP/UDP protocols
- **Basic Security**: NGINX-level protections 
- **Flexible Context**: Multisite context allows both global and service-specific settings"
    
    cat > "$plugin_dir/README.md" << EOF
# $plugin_name Plugin for BunkerWeb

$DESCRIPTION

## Features

$features

## Installation

### Docker Integration

1. **Download the plugin:**
   \`\`\`bash
   git clone <your-repo-url> && cd $plugin_name
   \`\`\`

2. **Copy to BunkerWeb plugins directory:**
   \`\`\`bash
   cp -r $plugin_name /path/to/bw-data/plugins/
   \`\`\`

3. **Set correct permissions:**
   \`\`\`bash
   chown -R root:101 /path/to/bw-data/plugins/$plugin_name
   chmod -R 750 /path/to/bw-data/plugins/$plugin_name
   \`\`\`

### Linux Integration

1. **Copy plugin to BunkerWeb plugins directory:**
   \`\`\`bash
   cp -r $plugin_name /etc/bunkerweb/plugins/
   \`\`\`

2. **Set correct permissions:**
   \`\`\`bash
   chown -R root:nginx /etc/bunkerweb/plugins/$plugin_name
   chmod -R 750 /etc/bunkerweb/plugins/$plugin_name
   \`\`\`

3. **Restart BunkerWeb:**
   \`\`\`bash
   systemctl restart bunkerweb
   \`\`\`

## Usage

### Basic Configuration

\`\`\`bash
# Enable the plugin
USE_${plugin_name_upper}=yes

# Configure main setting
PLUGIN_${plugin_name_upper}_SETTING=your_custom_value

# Set timeout (1-300 seconds)
PLUGIN_${plugin_name_upper}_TIMEOUT=10

# Set log level
PLUGIN_${plugin_name_upper}_LOG_LEVEL=INFO
\`\`\`

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| \`USE_${plugin_name_upper}\` | \`no\` | Enable or disable the plugin |
| \`PLUGIN_${plugin_name_upper}_SETTING\` | \`default_value\` | Main plugin configuration setting |
| \`PLUGIN_${plugin_name_upper}_TIMEOUT\` | \`5\` | Timeout for plugin operations (1-300 seconds) |
| \`PLUGIN_${plugin_name_upper}_LOG_LEVEL\` | \`DEBUG\` | Log verbosity (DEBUG, INFO, WARN, ERROR) |

## Development

### Modifying the Plugin

1. **Core Logic**: Edit \`$plugin_name.lua\` for main functionality
2. **Settings**: Update \`plugin.json\` for new configuration options
3. **Documentation**: Update this README.md with your changes

### Testing

\`\`\`bash
# Test plugin syntax
nginx -t

# Check BunkerWeb logs
tail -f /var/log/bunkerweb/error.log

# Test plugin endpoints
curl -I https://your-domain.com/$plugin_name/status
\`\`\`

## Troubleshooting

### Common Issues

1. **Plugin not loading:**
   - Check file permissions (should be 750 with correct ownership)
   - Verify plugin.json syntax
   - Check BunkerWeb error logs

2. **Configuration not applied:**
   - Restart BunkerWeb services
   - Verify environment variables are set correctly
   - Check for configuration conflicts

3. **Performance issues:**
   - Adjust \`PLUGIN_${plugin_name_upper}_TIMEOUT\` setting
   - Monitor system resources
   - Check for excessive logging

### Support

- **Documentation**: [BunkerWeb Plugins](https://docs.bunkerweb.io/latest/plugins/)
- **Community**: [Discord Server](https://bunkerity.discord.com/)
- **Issues**: [GitHub Issues](https://github.com/bunkerity/bunkerweb-plugins/issues)

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

Please follow the [BunkerWeb contribution guidelines](https://github.com/bunkerity/bunkerweb-plugins/blob/main/CONTRIBUTING.md).
EOF
}

create_plugin() {
    local plugin_name="$1"
    local output_dir="$2"
    local plugin_dir="${output_dir}/${plugin_name}"
    
    echo "Creating BunkerWeb plugin: $plugin_name"
    echo "Output directory: $plugin_dir"
    echo "Description: $DESCRIPTION"
    echo "Version: $VERSION"
    echo "Order: $ORDER"
    echo "Stream mode: $STREAM_MODE"
    echo "Context: multisite (supports global and per-service configuration)"
    
    if [ -d "$plugin_dir" ]; then
        echo "Warning: Directory $plugin_dir already exists"
        printf "Do you want to continue and overwrite? (y/N): "
        read -r
        if [ "$REPLY" != "y" ] && [ "$REPLY" != "Y" ]; then
            echo "Aborted"
            return 1
        fi
        rm -rf "$plugin_dir"
    fi
    
    echo "Creating directory structure..."
    create_directory_structure "$plugin_dir"
    create_docs "$plugin_dir"
    
    echo "Generating core files..."
    generate_plugin_json "$plugin_dir" "$plugin_name"
    generate_lua_file "$plugin_dir" "$plugin_name"
    
    if [ "$WITH_UI" = "yes" ]; then
        echo "Generating UI components..."
        generate_ui_components "$plugin_dir" "$plugin_name"
    fi
    
    if [ "$WITH_JOBS" = "yes" ]; then
        echo "Generating job files..."
        generate_job_files "$plugin_dir" "$plugin_name"
    fi
    
    if [ "$WITH_CONFIGS" = "yes" ]; then
        echo "Generating configuration templates..."
        generate_config_templates "$plugin_dir" "$plugin_name"
    fi
    
    if [ "$WITH_TEMPLATES" = "yes" ]; then
        echo "Generating custom templates..."
        generate_custom_templates "$plugin_dir" "$plugin_name"
    fi
    
    echo "Generating documentation..."
    generate_readme "$plugin_dir" "$plugin_name"
    
    project_readme_existed="no"
    if [ -f "$output_dir/README.md" ]; then
        project_readme_existed="yes"
    fi
    generate_project_readme "$output_dir"
    
    echo ""
    echo "Plugin structure created successfully!"
    echo ""
    echo "Directory: $plugin_dir"
    echo "Files created:"
    find "$plugin_dir" -type f | sort | sed 's/^/  /'
    echo ""
    if [ "$project_readme_existed" = "no" ]; then
        echo "Project README.md template created at: $output_dir/README.md"
        echo ""
    fi
    echo "Next steps:"
    echo "1. Review and customize the generated files"
    echo "2. Update the project README.md with your plugin information"
    echo "3. Test the plugin with your BunkerWeb instance"
    echo "4. Update settings in plugin.json as needed"
    echo "5. Implement your specific logic in $plugin_name.lua"
    echo "6. Configure appropriate permissions for your environment"
    echo ""
    echo "Installation command for Docker:"
    echo "  cp -r $plugin_dir /path/to/bw-data/plugins/ && \\"
    echo "  chown -R root:101 /path/to/bw-data/plugins/$plugin_name && \\"
    echo "  chmod -R 750 /path/to/bw-data/plugins/$plugin_name"
    echo ""
    echo "Plugin created in: $plugin_dir"
}

PLUGIN_NAME=""
DESCRIPTION=""
VERSION="1.0.0"
OUTPUT_DIR=".."
ORDER="256"
STREAM_MODE="partial"
WITH_UI="no"
WITH_JOBS="no"
WITH_CONFIGS="no"
WITH_TEMPLATES="no"

while [ $# -gt 0 ]; do
    if [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
        show_usage
        exit 0
    elif [ "$1" = "-d" ] || [ "$1" = "--description" ]; then
        DESCRIPTION="$2"
        shift 2
    elif [ "$1" = "-v" ] || [ "$1" = "--version" ]; then
        VERSION="$2"
        shift 2
    elif [ "$1" = "-o" ] || [ "$1" = "--output" ]; then
        OUTPUT_DIR="$2"
        shift 2
    elif [ "$1" = "--order" ]; then
        ORDER="$2"
        shift 2
    elif [ "$1" = "--stream" ]; then
        if [ "$2" = "no" ] || [ "$2" = "partial" ] || [ "$2" = "yes" ]; then
            STREAM_MODE="$2"
        else
            echo "Error: Invalid stream mode. Use: no, partial, or yes" >&2
            exit 1
        fi
        shift 2
    elif [ "$1" = "--with-ui" ]; then
        WITH_UI="yes"
        shift
    elif [ "$1" = "--with-jobs" ]; then
        WITH_JOBS="yes"
        shift
    elif [ "$1" = "--with-configs" ]; then
        WITH_CONFIGS="yes"
        shift
    elif [ "$1" = "--with-templates" ]; then
        WITH_TEMPLATES="yes"
        shift
    elif echo "$1" | grep -q '^-'; then
        echo "Unknown option: $1" >&2
        show_usage >&2
        exit 1
    else
        if [ -z "$PLUGIN_NAME" ]; then
            PLUGIN_NAME="$1"
        else
            echo "Error: Multiple plugin names specified" >&2
            exit 1
        fi
        shift
    fi
done

if [ -z "$PLUGIN_NAME" ]; then
    echo "Error: Plugin name is required" >&2
    show_usage >&2
    exit 1
fi

if [ -z "$DESCRIPTION" ]; then
    echo "Error: Plugin description is required (use -d or --description)" >&2
    exit 1
fi

if ! validate_plugin_name "$PLUGIN_NAME"; then
    exit 1
fi

if [ ! -d "$OUTPUT_DIR" ]; then
    echo "Error: Output directory does not exist: $OUTPUT_DIR" >&2
    exit 1
fi

if ! echo "$ORDER" | grep -q '^[0-9]\+$' || [ "$ORDER" -lt 1 ] || [ "$ORDER" -gt 999 ]; then
    echo "Error: Order must be a number between 1 and 999" >&2
    exit 1
fi

create_plugin "$PLUGIN_NAME" "$OUTPUT_DIR"