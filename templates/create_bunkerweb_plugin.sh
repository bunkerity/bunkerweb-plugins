#!/bin/bash
#

set -e

# Display usage information
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
    --with-jobs             Include job scheduler components (daily frequency)
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
- Jobs default to daily frequency. Edit plugin.json to change to hour/weekly/monthly.

EOF
}

# Validate plugin name format
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

# Create complete directory structure
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
        mkdir -p "$plugin_dir/confs/modsec"
        mkdir -p "$plugin_dir/confs/modsec-crs"
        mkdir -p "$plugin_dir/confs/stream"
        mkdir -p "$plugin_dir/confs/server-stream"
    fi
    
    if [ "$WITH_TEMPLATES" = "yes" ]; then
        mkdir -p "$plugin_dir/templates"
    fi
}

# Generate plugin.json metadata file
generate_plugin_json() {
    local plugin_dir="$1"
    local plugin_name="$2"
    local plugin_name_upper=$(echo "$plugin_name" | tr '[:lower:]' '[:upper:]')
    
    cat > "$plugin_dir/plugin.json" << EOF
{
    "id": "$plugin_name",
    "order": $ORDER,
    "name": "$(echo "$plugin_name" | sed 's/\(^\|_\|-\)\([a-z]\)/\U\2/g')",
    "description": "$DESCRIPTION",
    "version": "$VERSION",
    "stream": "$STREAM_MODE",
    "settings": {
        "USE_PLUGIN_${plugin_name_upper}": {
            "context": "multisite",
            "default": "no",
            "help": "Enable or disable the $plugin_name plugin.",
            "id": "use-plugin-${plugin_name}",
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
        },
        "PLUGIN_${plugin_name_upper}_TIMEOUT": {
            "context": "multisite",
            "default": "5",
            "help": "Timeout in seconds for $plugin_name operations.",
            "id": "plugin-${plugin_name}-timeout",
            "label": "${plugin_name} Timeout",
            "regex": "^[0-9]+$",
            "type": "text"
        },
        "PLUGIN_${plugin_name_upper}_LOG_LEVEL": {
            "context": "multisite",
            "default": "DEBUG",
            "help": "Log level for $plugin_name plugin.",
            "id": "plugin-${plugin_name}-log-level",
            "label": "${plugin_name} Log Level",
            "regex": "^(DEBUG|INFO|WARN|ERROR)$",
            "type": "select",
            "select": ["DEBUG", "INFO", "WARN", "ERROR"]
        }
    }$([ "$WITH_JOBS" = "yes" ] && echo ',
    "jobs": [
        {
            "name": "'"$plugin_name"'-job",
            "file": "'"$plugin_name"'-job.py",
            "every": "daily"
        }
    ]' || echo "")
}
EOF
}

# Generate main Lua plugin file
generate_lua_file() {
    local plugin_dir="$1"
    local plugin_name="$2"
    
    cat > "$plugin_dir/$plugin_name.lua" << 'EOF'
local class = require "middleclass"
local plugin = class("PLUGIN_NAME")

local logger = require "bunkerweb.logger"
local utils = require "bunkerweb.utils"
local datastore = require "bunkerweb.datastore"

-- Constructor function
function plugin:initialize(ctx)
    self.ctx = ctx
    self.logger = logger
    self.utils = utils
    self.datastore = datastore
end

-- Init phase - called during NGINX worker initialization
function plugin:init()
    if self.ctx.bw.variables["USE_PLUGIN_PLUGIN_NAME"] ~= "yes" then
        return self:ret(true, "Plugin disabled")
    end
    
    self.logger:log(ngx.NOTICE, "PLUGIN_NAME", "Initializing plugin")
    
    local ret, err = self.datastore:set("plugin_PLUGIN_NAME_status", "initialized")
    if not ret then
        self.logger:log(ngx.ERR, "PLUGIN_NAME", "Failed to set plugin status: " .. err)
        return self:ret(false, "Init failed: " .. err)
    end
    
    self.logger:log(ngx.NOTICE, "PLUGIN_NAME", "Plugin initialized successfully")
    return self:ret(true, "Init successful")
end

-- Access phase - called for each request before content is served
function plugin:access()
    if self.ctx.bw.variables["USE_PLUGIN_PLUGIN_NAME"] ~= "yes" then
        return self:ret(true, "Plugin disabled")
    end
    
    local start_time = ngx.now()
    self.logger:log(ngx.INFO, "PLUGIN_NAME", "Access phase started")
    
    local setting_value = self.ctx.bw.variables["PLUGIN_PLUGIN_NAME_SETTING"] or "default_value"
    local timeout = tonumber(self.ctx.bw.variables["PLUGIN_PLUGIN_NAME_TIMEOUT"]) or 5
    local log_level = self.ctx.bw.variables["PLUGIN_PLUGIN_NAME_LOG_LEVEL"] or "DEBUG"
    
    if not self:validate_settings(setting_value, timeout) then
        return self:ret(false, "Invalid settings")
    end
    
    local success, result = self:execute_main_logic(setting_value, timeout)
    if not success then
        self.logger:log(ngx.ERR, "PLUGIN_NAME", "Main logic failed: " .. (result or "unknown error"))
        return self:ret(false, "Plugin execution failed", 500)
    end
    
    local request_data = {
        uri = ngx.var.uri,
        method = ngx.var.request_method,
        remote_addr = ngx.var.remote_addr,
        timestamp = ngx.time(),
        result = result
    }
    
    local ret, err = self.datastore:set("plugin_PLUGIN_NAME_request_" .. ngx.var.request_id, 
                                       self.utils:json_encode(request_data), 300)
    if not ret then
        self.logger:log(ngx.WARN, "PLUGIN_NAME", "Failed to store request data: " .. err)
    end
    
    local duration = ngx.now() - start_time
    self.logger:log(ngx.INFO, "PLUGIN_NAME", 
                   string.format("Access phase completed in %.3f seconds", duration))
    
    return self:ret(true, "Access successful")
end

-- Log phase - called after the request has been processed
function plugin:log()
    if self.ctx.bw.variables["USE_PLUGIN_PLUGIN_NAME"] ~= "yes" then
        return self:ret(true, "Plugin disabled")
    end
    
    local log_level = self.ctx.bw.variables["PLUGIN_PLUGIN_NAME_LOG_LEVEL"] or "DEBUG"
    
    local request_data_str, err = self.datastore:get("plugin_PLUGIN_NAME_request_" .. ngx.var.request_id)
    if request_data_str then
        local request_data = self.utils:json_decode(request_data_str)
        if request_data then
            self:log_request_details(request_data, log_level)
        end
        
        self.datastore:delete("plugin_PLUGIN_NAME_request_" .. ngx.var.request_id)
    end
    
    return self:ret(true, "Log successful")
end

-- Preread phase - called for stream module (TCP/UDP)
function plugin:preread()
    if self.ctx.bw.variables["USE_PLUGIN_PLUGIN_NAME"] ~= "yes" then
        return self:ret(true, "Plugin disabled")
    end
    
    self.logger:log(ngx.INFO, "PLUGIN_NAME", "Preread phase executed")
    
    local client_addr = ngx.var.remote_addr
    local server_port = ngx.var.server_port
    
    self.logger:log(ngx.INFO, "PLUGIN_NAME", 
                   string.format("Stream connection from %s to port %s", client_addr, server_port))
    
    return self:ret(true, "Preread successful")
end

-- Validate plugin settings
function plugin:validate_settings(setting_value, timeout)
    if not setting_value or setting_value == "" then
        self.logger:log(ngx.ERR, "PLUGIN_NAME", "Setting value is empty")
        return false
    end
    
    if timeout <= 0 or timeout > 60 then
        self.logger:log(ngx.ERR, "PLUGIN_NAME", "Invalid timeout value: " .. timeout)
        return false
    end
    
    return true
end

-- Execute main plugin logic
function plugin:execute_main_logic(setting_value, timeout)
    self.logger:log(ngx.INFO, "PLUGIN_NAME", 
                   string.format("Executing with setting: %s, timeout: %d", setting_value, timeout))
    
    local allow_request = true
    local reason = "Request allowed by plugin"
    
    return allow_request, reason
end

-- Log request details based on log level
function plugin:log_request_details(request_data, log_level)
    local levels = {DEBUG = 4, INFO = 3, WARN = 2, ERROR = 1}
    local current_level = levels[log_level] or 4
    
    if current_level >= 3 then
        self.logger:log(ngx.INFO, "PLUGIN_NAME", 
                       string.format("Request processed: %s %s from %s", 
                                   request_data.method, request_data.uri, request_data.remote_addr))
    end
    
    if current_level >= 4 then
        self.logger:log(ngx.DEBUG, "PLUGIN_NAME", 
                       string.format("Request details: %s", self.utils:json_encode(request_data)))
    end
end

-- Helper function to return consistent results
function plugin:ret(ok, msg, status, redirect_url)
    return ok, msg, status or nil, redirect_url or nil
end

return plugin
EOF

    sed -i.bak "s|PLUGIN_NAME|${plugin_name}|g" "$plugin_dir/$plugin_name.lua"
    rm -f "$plugin_dir/$plugin_name.lua.bak"
}

# Generate complete UI components
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
            
            config_result = save_configuration(data)
            
            if config_result["success"]:
                return jsonify({
                    "success": True,
                    "message": "Configuration saved successfully",
                    "data": config_result["data"]
                })
            else:
                return jsonify({
                    "error": config_result["message"]
                }), 500
                
        except Exception as e:
            current_app.logger.error(f"$plugin_name plugin error: {str(e)}")
            return jsonify({"error": f"Internal error: {str(e)}"}), 500


def validate_configuration(data):
    """
    Validate plugin configuration data
    """
    required_fields = ["enabled", "setting", "timeout", "log_level"]
    
    for field in required_fields:
        if field not in data:
            return {"valid": False, "message": f"Missing required field: {field}"}
    
    try:
        timeout = int(data["timeout"])
        if timeout <= 0 or timeout > 300:
            return {"valid": False, "message": "Timeout must be between 1 and 300 seconds"}
    except (ValueError, TypeError):
        return {"valid": False, "message": "Timeout must be a valid number"}
    
    valid_log_levels = ["DEBUG", "INFO", "WARN", "ERROR"]
    if data["log_level"] not in valid_log_levels:
        return {"valid": False, "message": f"Log level must be one of: {', '.join(valid_log_levels)}"}
    
    return {"valid": True, "message": "Configuration is valid"}


def save_configuration(data):
    """
    Save plugin configuration
    """
    try:
        config = {
            "enabled": bool(data.get("enabled", False)),
            "setting": str(data.get("setting", "")).strip(),
            "timeout": int(data.get("timeout", 5)),
            "log_level": str(data.get("log_level", "INFO")),
            "updated_at": datetime.utcnow().isoformat(),
            "updated_by": "web_ui"
        }
        
        config_path = os.path.join("/tmp", f"$plugin_name_config.json")
        with open(config_path, "w") as f:
            json.dump(config, f, indent=2)
        
        current_app.logger.info(f"$plugin_name configuration saved successfully")
        
        return {
            "success": True,
            "data": config,
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
        .plugin-container {
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
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
            padding: 10px 12px;
            border: 1px solid #ced4da;
            border-radius: 4px;
            font-size: 14px;
            transition: border-color 0.15s ease-in-out, box-shadow 0.15s ease-in-out;
        }
        .form-control:focus {
            outline: 0;
            border-color: #80bdff;
            box-shadow: 0 0 0 0.2rem rgba(0, 123, 255, 0.25);
        }
        .form-check {
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .form-check-input {
            width: 18px;
            height: 18px;
        }
        .btn {
            display: inline-block;
            padding: 10px 20px;
            font-size: 14px;
            font-weight: 600;
            text-align: center;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            transition: all 0.15s ease-in-out;
        }
        .btn-primary {
            background-color: #007bff;
            color: white;
        }
        .btn-primary:hover {
            background-color: #0056b3;
        }
        .btn-secondary {
            background-color: #6c757d;
            color: white;
            margin-left: 10px;
        }
        .btn-secondary:hover {
            background-color: #545b62;
        }
        .status-message {
            padding: 12px 16px;
            border-radius: 4px;
            margin-top: 15px;
            font-weight: 500;
        }
        .status-message.success {
            background-color: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }
        .status-message.error {
            background-color: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }
        .loading {
            opacity: 0.6;
            pointer-events: none;
        }
        @media (max-width: 600px) {
            .plugin-container {
                padding: 10px;
            }
            .plugin-info {
                grid-template-columns: 1fr;
            }
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
                <div class="info-label">Version</div>
                <div class="info-value">{{ plugin_version }}</div>
            </div>
            <div class="info-item">
                <div class="info-label">Status</div>
                <div class="info-value" id="plugin-status">Loading...</div>
            </div>
            <div class="info-item">
                <div class="info-label">Last Activity</div>
                <div class="info-value" id="last-activity">-</div>
            </div>
            <div class="info-item">
                <div class="info-label">Requests Processed</div>
                <div class="info-value" id="requests-processed">-</div>
            </div>
        </div>
        
        <form id="plugin-form" class="form-section">
            <h3>Configuration</h3>
            
            <div class="form-group">
                <div class="form-check">
                    <input type="checkbox" class="form-check-input" id="plugin-enabled" name="enabled" checked>
                    <label for="plugin-enabled" class="form-label">Enable Plugin</label>
                </div>
            </div>
            
            <div class="form-group">
                <label for="plugin-setting" class="form-label">Main Setting</label>
                <input type="text" class="form-control" id="plugin-setting" name="setting" 
                       placeholder="Enter configuration value" value="default_value" required>
                <small class="form-text text-muted">Configure the main setting for this plugin</small>
            </div>
            
            <div class="form-group">
                <label for="plugin-timeout" class="form-label">Timeout (seconds)</label>
                <input type="number" class="form-control" id="plugin-timeout" name="timeout" 
                       min="1" max="300" value="5" required>
                <small class="form-text text-muted">Timeout for plugin operations (1-300 seconds)</small>
            </div>
            
            <div class="form-group">
                <label for="plugin-log-level" class="form-label">Log Level</label>
                <select class="form-control" id="plugin-log-level" name="log_level" required>
                    <option value="DEBUG" selected>Debug</option>
                    <option value="INFO">Info</option>
                    <option value="WARN">Warning</option>
                    <option value="ERROR">Error</option>
                </select>
                <small class="form-text text-muted">Set the logging verbosity level</small>
            </div>
            
            <div class="form-group">
                <button type="submit" class="btn btn-primary">Save Configuration</button>
                <button type="button" class="btn btn-secondary" onclick="resetForm()">Reset</button>
            </div>
        </form>
        
        <div id="status-message" class="status-message" style="display: none;"></div>
    </div>
    
    <script>
        let originalFormData = {};
        
        document.addEventListener('DOMContentLoaded', function() {
            loadPluginStatus();
            storeOriginalFormData();
            setInterval(loadPluginStatus, 30000);
        });
        
        function storeOriginalFormData() {
            const form = document.getElementById('plugin-form');
            const formData = new FormData(form);
            originalFormData = {
                enabled: document.getElementById('plugin-enabled').checked,
                setting: formData.get('setting'),
                timeout: formData.get('timeout'),
                log_level: formData.get('log_level') || 'DEBUG'
            };
        }
        
        function loadPluginStatus() {
            document.getElementById('plugin-status').textContent = 'Active';
            document.getElementById('last-activity').textContent = new Date().toLocaleString();
            document.getElementById('requests-processed').textContent = '12,345';
        }
        
        document.getElementById('plugin-form').addEventListener('submit', function(e) {
            e.preventDefault();
            
            const form = this;
            const formData = new FormData(form);
            const data = {
                enabled: document.getElementById('plugin-enabled').checked,
                setting: formData.get('setting'),
                timeout: parseInt(formData.get('timeout')),
                log_level: formData.get('log_level'),
                timestamp: new Date().toISOString()
            };
            
            form.classList.add('loading');
            showStatus('Saving configuration...', 'info');
            
            fetch('', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(data)
            })
            .then(response => response.json())
            .then(data => {
                form.classList.remove('loading');
                if (data.success) {
                    showStatus('Configuration saved successfully!', 'success');
                    storeOriginalFormData();
                } else {
                    showStatus('Error: ' + data.error, 'error');
                }
            })
            .catch(error => {
                form.classList.remove('loading');
                console.error('Error:', error);
                showStatus('Error saving configuration: ' + error.message, 'error');
            });
        });
        
        function resetForm() {
            document.getElementById('plugin-enabled').checked = originalFormData.enabled;
            document.getElementById('plugin-setting').value = originalFormData.setting;
            document.getElementById('plugin-timeout').value = originalFormData.timeout;
            document.getElementById('plugin-log-level').value = originalFormData.log_level;
            showStatus('Form reset to original values', 'info');
        }
        
        function showStatus(message, type) {
            const statusEl = document.getElementById('status-message');
            statusEl.textContent = message;
            statusEl.className = 'status-message ' + type;
            statusEl.style.display = 'block';
            
            if (type === 'success' || type === 'info') {
                setTimeout(() => {
                    statusEl.style.display = 'none';
                }, 5000);
            }
        }
    </script>
</body>
</html>
EOF

    cat > "$plugin_dir/ui/hooks.py" << EOF
#!/usr/bin/env python3

import logging
from flask import current_app, g


def before_first_request():
    """
    Hook executed before the first request to the plugin
    """
    current_app.logger.info("$plugin_name plugin UI initialized")


def before_request():
    """
    Hook executed before each request to the plugin
    """
    g.plugin_name = "$plugin_name"
    g.plugin_version = "$VERSION"
    
    if current_app.logger.isEnabledFor(logging.DEBUG):
        current_app.logger.debug(f"$plugin_name plugin processing request")


def after_request(response):
    """
    Hook executed after each request to the plugin
    """
    response.headers['X-Plugin-Name'] = '$plugin_name'
    response.headers['X-Plugin-Version'] = '$VERSION'
    
    if current_app.logger.isEnabledFor(logging.DEBUG):
        current_app.logger.debug(f"$plugin_name plugin response: {response.status_code}")
    
    return response


def teardown_request(exception):
    """
    Hook executed when tearing down a request
    """
    if exception:
        current_app.logger.error(f"$plugin_name plugin request teardown with exception: {exception}")
    
    if hasattr(g, 'plugin_resources'):
        pass


def teardown_appcontext(exception):
    """
    Hook executed when tearing down the application context
    """
    if exception:
        current_app.logger.error(f"$plugin_name plugin app context teardown with exception: {exception}")
EOF
}

# Generate job scheduler files
generate_job_files() {
    local plugin_dir="$1"
    local plugin_name="$2"
    local plugin_name_upper=$(echo "$plugin_name" | tr '[:lower:]' '[:upper:]')
    
    cat > "$plugin_dir/jobs/$plugin_name-job.py" << EOF
#!/usr/bin/env python3

"""
$plugin_name Plugin - Scheduled Job

This job runs daily by default. To change the frequency, modify the 'every' 
field in plugin.json to one of: hour, daily, weekly, monthly

Job performs:
- Data cleanup and maintenance
- Statistics processing and aggregation  
- Health checks and validation
- Metrics updates and monitoring
"""

import os
import sys
import json
import time
import logging
import traceback
from pathlib import Path
from datetime import datetime, timedelta


def main():
    """
    Main job function for $plugin_name plugin
    Executes daily maintenance and data processing tasks
    """
    logger = setup_logging()
    logger.info("Starting $plugin_name scheduled job")
    
    try:
        config = read_plugin_config()
        
        tasks_completed = 0
        
        if cleanup_old_data(config, logger):
            tasks_completed = tasks_completed + 1
        
        if process_data(config, logger):
            tasks_completed = tasks_completed + 1
        
        if update_statistics(config, logger):
            tasks_completed = tasks_completed + 1
        
        if perform_health_check(config, logger):
            tasks_completed = tasks_completed + 1
        
        logger.info(f"$plugin_name job completed successfully. Tasks completed: {tasks_completed}/4")
        return 0
        
    except Exception as e:
        logger.error(f"$plugin_name job failed with error: {str(e)}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        return 1


def setup_logging():
    """
    Configure logging for the scheduled job
    """
    log_dir = Path("/var/log/bunkerweb")
    log_dir.mkdir(exist_ok=True)
    
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler(log_dir / "$plugin_name-job.log")
        ]
    )
    
    logger = logging.getLogger('$plugin_name-job')
    logger.setLevel(logging.DEBUG)
    
    return logger


def read_plugin_config():
    """
    Read plugin configuration from environment variables and config files
    """
    config = {
        'enabled': os.getenv('USE_PLUGIN_${plugin_name_upper}', 'no').lower() == 'yes',
        'setting': os.getenv('PLUGIN_${plugin_name_upper}_SETTING', 'default_value'),
        'timeout': int(os.getenv('PLUGIN_${plugin_name_upper}_TIMEOUT', '5')),
        'log_level': os.getenv('PLUGIN_${plugin_name_upper}_LOG_LEVEL', 'DEBUG'),
        'data_retention_days': int(os.getenv('PLUGIN_${plugin_name_upper}_DATA_RETENTION_DAYS', '30'))
    }
    
    config_file = Path('/etc/bunkerweb/plugins/$plugin_name/config.json')
    if config_file.exists():
        try:
            with open(config_file, 'r') as f:
                file_config = json.load(f)
                config.update(file_config)
        except Exception as e:
            logging.warning(f"Failed to read config file: {e}")
    
    return config


def cleanup_old_data(config, logger):
    """
    Clean up old data files and logs
    """
    try:
        if not config['enabled']:
            logger.info("Plugin disabled, skipping cleanup")
            return True
        
        cutoff_date = datetime.now() - timedelta(days=config['data_retention_days'])
        data_dir = Path('/var/lib/bunkerweb/$plugin_name')
        
        if not data_dir.exists():
            logger.info("Data directory does not exist, creating it")
            data_dir.mkdir(parents=True, exist_ok=True)
            return True
        
        files_removed = 0
        for file_path in data_dir.rglob('*'):
            if file_path.is_file():
                file_mtime = datetime.fromtimestamp(file_path.stat().st_mtime)
                if file_mtime < cutoff_date:
                    file_path.unlink()
                    files_removed = files_removed + 1
        
        logger.info(f"Cleanup completed. Removed {files_removed} old files")
        return True
        
    except Exception as e:
        logger.error(f"Cleanup failed: {str(e)}")
        return False


def process_data(config, logger):
    """
    Process accumulated data and generate reports
    """
    try:
        if not config['enabled']:
            logger.info("Plugin disabled, skipping data processing")
            return True
        
        start_time = time.time()
        
        processed_requests = process_request_logs(config, logger)
        
        stats = generate_statistics(processed_requests, logger)
        
        save_processed_data(stats, logger)
        
        processing_time = time.time() - start_time
        logger.info(f"Data processing completed in {processing_time:.2f} seconds. "
                   f"Processed {processed_requests} requests")
        return True
        
    except Exception as e:
        logger.error(f"Data processing failed: {str(e)}")
        return False


def process_request_logs(config, logger):
    """
    Process request logs and extract relevant data
    """
    processed_count = 0
    log_dir = Path('/var/log/bunkerweb')
    
    for log_file in log_dir.glob('access*.log'):
        try:
            with open(log_file, 'r') as f:
                for line in f:
                    if '$plugin_name' in line:
                        processed_count = processed_count + 1
        except Exception as e:
            logger.warning(f"Failed to process log file {log_file}: {e}")
    
    return processed_count


def generate_statistics(processed_requests, logger):
    """
    Generate statistics from processed data
    """
    stats = {
        'timestamp': datetime.now().isoformat(),
        'processed_requests': processed_requests,
        'plugin_version': '$VERSION',
        'uptime': time.time(),
        'memory_usage': 'N/A',
        'cpu_usage': 'N/A'
    }
    
    logger.info(f"Generated statistics: {json.dumps(stats, indent=2)}")
    return stats


def save_processed_data(stats, logger):
    """
    Save processed data and statistics
    """
    try:
        stats_dir = Path('/var/lib/bunkerweb/$plugin_name/stats')
        stats_dir.mkdir(parents=True, exist_ok=True)
        
        today = datetime.now().strftime('%Y-%m-%d')
        stats_file = stats_dir / f"stats_{today}.json"
        
        with open(stats_file, 'w') as f:
            json.dump(stats, f, indent=2)
        
        logger.info(f"Statistics saved to {stats_file}")
        
    except Exception as e:
        logger.error(f"Failed to save statistics: {str(e)}")
        raise


def update_statistics(config, logger):
    """
    Update runtime statistics and metrics
    """
    try:
        if not config['enabled']:
            logger.info("Plugin disabled, skipping statistics update")
            return True
        
        metrics = {
            'last_job_run': datetime.now().isoformat(),
            'job_run_count': get_job_run_count() + 1,
            'plugin_status': 'active' if config['enabled'] else 'disabled',
            'config_hash': hash(str(sorted(config.items())))
        }
        
        save_metrics(metrics, logger)
        logger.info("Statistics updated successfully")
        return True
        
    except Exception as e:
        logger.error(f"Statistics update failed: {str(e)}")
        return False


def get_job_run_count():
    """
    Get the number of times this job has been executed
    """
    try:
        metrics_file = Path('/var/lib/bunkerweb/$plugin_name/metrics.json')
        if metrics_file.exists():
            with open(metrics_file, 'r') as f:
                metrics = json.load(f)
                return metrics.get('job_run_count', 0)
    except Exception:
        pass
    
    return 0


def save_metrics(metrics, logger):
    """
    Save runtime metrics to file
    """
    try:
        metrics_dir = Path('/var/lib/bunkerweb/$plugin_name')
        metrics_dir.mkdir(parents=True, exist_ok=True)
        
        metrics_file = metrics_dir / 'metrics.json'
        with open(metrics_file, 'w') as f:
            json.dump(metrics, f, indent=2)
        
        logger.debug(f"Metrics saved to {metrics_file}")
        
    except Exception as e:
        logger.error(f"Failed to save metrics: {str(e)}")
        raise


def perform_health_check(config, logger):
    """
    Perform health check and validation
    """
    try:
        health_status = {
            'plugin_enabled': config['enabled'],
            'config_valid': validate_config(config),
            'data_directory_writable': check_data_directory(),
            'log_directory_writable': check_log_directory(),
            'timestamp': datetime.now().isoformat()
        }
        
        all_healthy = all(health_status.values() if isinstance(v, bool) else [True] 
                         for v in health_status.values())
        
        if all_healthy:
            logger.info("Health check passed")
        else:
            logger.warning(f"Health check issues detected: {health_status}")
        
        save_health_status(health_status, logger)
        
        return all_healthy
        
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        return False


def validate_config(config):
    """
    Validate plugin configuration
    """
    try:
        if not isinstance(config.get('timeout'), int) or config['timeout'] <= 0:
            return False
        
        if config.get('log_level') not in ['DEBUG', 'INFO', 'WARN', 'ERROR']:
            return False
        
        return True
        
    except Exception:
        return False


def check_data_directory():
    """
    Check if data directory is writable
    """
    try:
        data_dir = Path('/var/lib/bunkerweb/$plugin_name')
        data_dir.mkdir(parents=True, exist_ok=True)
        
        test_file = data_dir / '.write_test'
        test_file.write_text('test')
        test_file.unlink()
        
        return True
        
    except Exception:
        return False


def check_log_directory():
    """
    Check if log directory is writable
    """
    try:
        log_dir = Path('/var/log/bunkerweb')
        test_file = log_dir / '.write_test'
        test_file.write_text('test')
        test_file.unlink()
        
        return True
        
    except Exception:
        return False


def save_health_status(health_status, logger):
    """
    Save health check results
    """
    try:
        health_dir = Path('/var/lib/bunkerweb/$plugin_name')
        health_dir.mkdir(parents=True, exist_ok=True)
        
        health_file = health_dir / 'health.json'
        with open(health_file, 'w') as f:
            json.dump(health_status, f, indent=2)
        
        logger.debug(f"Health status saved to {health_file}")
        
    except Exception as e:
        logger.error(f"Failed to save health status: {str(e)}")


if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)
EOF

    chmod +x "$plugin_dir/jobs/$plugin_name-job.py"
}

# Generate comprehensive NGINX configuration templates
generate_config_templates() {
    local plugin_dir="$1"
    local plugin_name="$2"
    local plugin_name_upper=$(echo "$plugin_name" | tr '[:lower:]' '[:upper:]')
    
    cat > "$plugin_dir/confs/server-http/$plugin_name.conf" << EOF
# $plugin_name Plugin - Server HTTP Configuration
# Included in server {} context for each virtual host

{% if USE_PLUGIN_${plugin_name_upper} == "yes" %}

# Plugin endpoint for status and configuration
location /$plugin_name {
    default_type 'application/json';
    access_log off;
    
    content_by_lua_block {
        local cjson = require "cjson"
        local plugin_setting = "{{ PLUGIN_${plugin_name_upper}_SETTING }}"
        local plugin_timeout = "{{ PLUGIN_${plugin_name_upper}_TIMEOUT }}"
        
        local response = {
            plugin = "$plugin_name",
            version = "$VERSION",
            status = "active",
            setting = plugin_setting,
            timeout = tonumber(plugin_timeout),
            timestamp = ngx.time()
        }
        
        ngx.header["Content-Type"] = "application/json"
        ngx.header["Cache-Control"] = "no-cache"
        ngx.say(cjson.encode(response))
    }
}

# Status endpoint for health checks
location = /$plugin_name/status {
    access_log off;
    default_type 'text/plain';
    
    content_by_lua_block {
        ngx.header["Content-Type"] = "text/plain"
        ngx.header["Cache-Control"] = "no-cache"
        ngx.say("$plugin_name plugin is active")
    }
}

# Metrics endpoint for monitoring
location = /$plugin_name/metrics {
    access_log off;
    default_type 'text/plain';
    
    content_by_lua_block {
        local datastore = require "bunkerweb.datastore"
        
        local requests_count, _ = datastore:get("plugin_${plugin_name}_requests_count")
        local last_request, _ = datastore:get("plugin_${plugin_name}_last_request")
        
        local metrics = string.format(
            "# HELP ${plugin_name}_requests_total Total requests processed by $plugin_name\\n" ..
            "# TYPE ${plugin_name}_requests_total counter\\n" ..
            "${plugin_name}_requests_total %s\\n" ..
            "# HELP ${plugin_name}_last_request_timestamp Last request timestamp\\n" ..
            "# TYPE ${plugin_name}_last_request_timestamp gauge\\n" ..
            "${plugin_name}_last_request_timestamp %s\\n",
            requests_count or "0",
            last_request or "0"
        )
        
        ngx.header["Content-Type"] = "text/plain"
        ngx.say(metrics)
    }
}

# Apply rate limiting to plugin endpoints
location ~* ^/$plugin_name/(status|metrics)\$ {
    limit_req zone=req_limit_per_ip burst=10 nodelay;
}

{% endif %}
EOF

    cat > "$plugin_dir/confs/http/$plugin_name.conf" << EOF
# $plugin_name Plugin - HTTP Configuration
# Included in http {} context

{% if USE_PLUGIN_${plugin_name_upper} == "yes" %}

# Custom log format for plugin requests
log_format ${plugin_name}_access_log 
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
# Applied to default server block

{% if USE_PLUGIN_${plugin_name_upper} == "yes" %}

# Block plugin endpoints on default server
location /$plugin_name {
    return 444;
}

{% endif %}
EOF

    cat > "$plugin_dir/confs/modsec/$plugin_name.conf" << EOF
# $plugin_name Plugin - ModSecurity Configuration

{% if USE_PLUGIN_${plugin_name_upper} == "yes" %}

# Custom ModSecurity rules for $plugin_name plugin
SecRule REQUEST_URI "@beginsWith /$plugin_name" \\
    "id:${plugin_name}001,\\
    phase:1,\\
    pass,\\
    msg:'$plugin_name plugin: Processing plugin request',\\
    tag:'$plugin_name',\\
    logdata:'Plugin setting: {{ PLUGIN_${plugin_name_upper}_SETTING }}',\\
    rev:'1'"

# Block suspicious patterns in plugin parameters
SecRule ARGS "@detectSQLi" \\
    "id:${plugin_name}002,\\
    phase:2,\\
    block,\\
    msg:'$plugin_name plugin: SQL injection attempt detected',\\
    logdata:'Matched Data: %{MATCHED_VAR} found within %{MATCHED_VAR_NAME}',\\
    severity:'CRITICAL',\\
    tag:'$plugin_name',\\
    tag:'sql-injection',\\
    rev:'1'"

SecRule ARGS "@detectXSS" \\
    "id:${plugin_name}003,\\
    phase:2,\\
    block,\\
    msg:'$plugin_name plugin: XSS attempt detected',\\
    logdata:'Matched Data: %{MATCHED_VAR} found within %{MATCHED_VAR_NAME}',\\
    severity:'HIGH',\\
    tag:'$plugin_name',\\
    tag:'xss',\\
    rev:'1'"

# Allow legitimate plugin status checks
SecRule REQUEST_URI "@streq /$plugin_name/status" \\
    "id:${plugin_name}004,\\
    phase:1,\\
    pass,\\
    msg:'$plugin_name plugin: Allow status endpoint',\\
    tag:'$plugin_name',\\
    ctl:ruleRemoveById=${plugin_name}002,\\
    ctl:ruleRemoveById=${plugin_name}003,\\
    rev:'1'"

{% endif %}
EOF

    cat > "$plugin_dir/confs/modsec-crs/$plugin_name.conf" << EOF
# $plugin_name Plugin - ModSecurity CRS Configuration
# Rules to be loaded before the CRS

{% if USE_PLUGIN_${plugin_name_upper} == "yes" %}

# Whitelist plugin endpoints from certain CRS rules
SecRule REQUEST_URI "@rx ^/$plugin_name/(status|metrics)\$" \\
    "id:${plugin_name}100,\\
    phase:1,\\
    pass,\\
    msg:'$plugin_name plugin: Whitelist plugin endpoints',\\
    tag:'$plugin_name',\\
    ctl:ruleRemoveTargetById=920350;ARGS,\\
    ctl:ruleRemoveTargetById=920360;ARGS,\\
    rev:'1'"

{% endif %}
EOF

    cat > "$plugin_dir/confs/stream/$plugin_name.conf" << EOF
# $plugin_name Plugin - Stream Configuration
# Included in stream {} context

{% if USE_PLUGIN_${plugin_name_upper} == "yes" and LISTEN_STREAM == "yes" %}

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
# Included in server {} context for stream servers

{% if USE_PLUGIN_${plugin_name_upper} == "yes" and LISTEN_STREAM == "yes" %}

# Custom stream processing
preread_by_lua_block {
    local plugin_setting = "{{ PLUGIN_${plugin_name_upper}_SETTING }}"
    ngx.log(ngx.INFO, "$plugin_name: Processing stream connection with setting: " .. plugin_setting)
}

{% endif %}
EOF
}

# Generate custom configuration templates
generate_custom_templates() {
    local plugin_dir="$1"
    local plugin_name="$2"
    local plugin_name_upper=$(echo "$plugin_name" | tr '[:lower:]' '[:upper:]')
    
    cat > "$plugin_dir/templates/$plugin_name-template.json" << EOF
{
    "name": "$plugin_name-template",
    "description": "Template for $plugin_name plugin configuration",
    "version": "$VERSION",
    "settings": {
        "USE_PLUGIN_${plugin_name_upper}": "yes",
        "PLUGIN_${plugin_name_upper}_SETTING": "production_value",
        "PLUGIN_${plugin_name_upper}_TIMEOUT": "10",
        "PLUGIN_${plugin_name_upper}_LOG_LEVEL": "DEBUG"
    },
    "custom_configs": {
        "server-http": {
            "${plugin_name}-custom.conf": "# Custom configuration for $plugin_name\\nlocation /${plugin_name}-custom {\\n    return 200 'Custom endpoint active';\\n}"
        }
    }
}
EOF

    cat > "$plugin_dir/templates/$plugin_name-dev.json" << EOF
{
    "name": "$plugin_name-dev",
    "description": "Development template for $plugin_name plugin",
    "version": "$VERSION",
    "settings": {
        "USE_PLUGIN_${plugin_name_upper}": "yes",
        "PLUGIN_${plugin_name_upper}_SETTING": "development_value",
        "PLUGIN_${plugin_name_upper}_TIMEOUT": "30",
        "PLUGIN_${plugin_name_upper}_LOG_LEVEL": "DEBUG"
    }
}
EOF

    cat > "$plugin_dir/templates/$plugin_name-prod.json" << EOF
{
    "name": "$plugin_name-prod",
    "description": "Production template for $plugin_name plugin",
    "version": "$VERSION",
    "settings": {
        "USE_PLUGIN_${plugin_name_upper}": "yes",
        "PLUGIN_${plugin_name_upper}_SETTING": "production_value",
        "PLUGIN_${plugin_name_upper}_TIMEOUT": "5",
        "PLUGIN_${plugin_name_upper}_LOG_LEVEL": "DEBUG"
    }
}
EOF

    mkdir -p "$plugin_dir/templates/$plugin_name-template/configs/server-http"
    cat > "$plugin_dir/templates/$plugin_name-template/configs/server-http/custom-endpoint.conf" << EOF
# Custom endpoint configuration for $plugin_name template
location /${plugin_name}-template {
    default_type 'application/json';
    content_by_lua_block {
        local cjson = require "cjson"
        ngx.say(cjson.encode({
            message = "Template endpoint active",
            plugin = "$plugin_name",
            template = "$plugin_name-template"
        }))
    }
}
EOF
}

# Generate project-level README template for developers
generate_project_readme() {
    local output_dir="$1"
    local project_readme="$output_dir/README.md"
    
    if [ -f "$project_readme" ]; then
        echo "Project README.md already exists, skipping..."
        return 0
    fi
    
    cat > "$project_readme" << 'EOF'
# BunkerWeb Plugins Project

This repository contains custom BunkerWeb plugins for enhanced web application security.

## Overview

BunkerWeb is a next-generation Web Application Firewall (WAF) that provides comprehensive security for your web services. This project extends BunkerWeb's capabilities with custom plugins tailored to specific security requirements.

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

<!-- Add your plugins here as you create them -->
| Plugin | Description | Version | Features |
|--------|-------------|---------|----------|
| [example-plugin](./example-plugin/) | Example plugin description | 1.0.0 | Feature list |

> **Tip:** Add each new plugin to this table with a link to its directory and a brief description.

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

### Configuration Examples

**Docker Compose:**
```yaml
version: '3.8'
services:
  bunkerweb:
    image: bunkerity/bunkerweb:latest
    environment:
      - USE_PLUGIN_MYPLUGIN=yes
      - PLUGIN_MYPLUGIN_SETTING=production_value
    volumes:
      - ./bw-data:/data
```

**Kubernetes:**
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  annotations:
    bunkerweb.io/USE_PLUGIN_MYPLUGIN: "yes"
    bunkerweb.io/PLUGIN_MYPLUGIN_SETTING: "kubernetes_value"
```

## Development

### Creating New Plugins

Use the provided plugin template generator:

```bash
cd templates/
./create_bunkerweb_plugin.sh -d "Your plugin description" your-plugin-name
```

Available options:
- `--with-ui`: Include web UI components
- `--with-jobs`: Include scheduled jobs
- `--with-configs`: Include NGINX configuration templates
- `--with-templates`: Include configuration templates

### Development Guidelines

1. **Follow BunkerWeb Standards:**
   - Use multisite context for all settings
   - Implement proper error handling
   - Include comprehensive logging
   - Follow naming conventions: `PLUGIN_PLUGINNAME_SETTING`

2. **Testing:**
   - Test with single-site and multisite configurations
   - Verify all NGINX phases (init, access, log, preread)
   - Test with different log levels
   - Validate configuration templates

3. **Documentation:**
   - Update plugin README.md with usage examples
   - Document all configuration options
   - Include troubleshooting section
   - Provide Docker and Kubernetes examples

### Plugin Development Workflow

1. **Create Plugin:**
   ```bash
   cd templates/
   ./create_bunkerweb_plugin.sh -d "My security plugin" --with-ui my-plugin
   ```

2. **Implement Logic:**
   - Edit `my-plugin.lua` for core functionality
   - Update `plugin.json` for settings
   - Customize UI components if needed

3. **Test Plugin:**
   ```bash
   # Install in test environment
   cp -r my-plugin /path/to/test-bw/plugins/
   
   # Configure and test
   USE_PLUGIN_MYPLUGIN=yes
   ```

4. **Document:**
   - Update plugin README.md
   - Add entry to this project README in the "Available Plugins" table
   - Include configuration examples

## Troubleshooting

### Common Issues

1. **Plugin Not Loading:**
   - Check file permissions (750 with correct ownership)
   - Verify plugin.json syntax
   - Check BunkerWeb error logs

2. **Configuration Not Applied:**
   - Restart BunkerWeb services
   - Verify environment variables
   - Check for multisite configuration conflicts

3. **Performance Issues:**
   - Adjust plugin timeout settings
   - Review log levels (use INFO for production)
   - Monitor system resources

### Debugging

1. **Enable Debug Logging:**
   ```bash
   PLUGIN_PLUGINNAME_LOG_LEVEL=DEBUG
   ```

2. **Check Logs:**
   ```bash
   # BunkerWeb logs
   tail -f /var/log/bunkerweb/error.log
   
   # Plugin-specific logs
   grep "PLUGINNAME" /var/log/bunkerweb/error.log
   ```

3. **Test Plugin Endpoints:**
   ```bash
   curl -I https://your-domain.com/plugin-name/status
   ```

## Contributing

1. Fork this repository
2. Create a feature branch
3. Develop your plugin following the guidelines
4. Add comprehensive tests
5. Update documentation
6. Submit a pull request

### Code Review Checklist

- [ ] Plugin follows BunkerWeb naming conventions
- [ ] All settings use multisite context
- [ ] Comprehensive error handling implemented
- [ ] Documentation includes examples
- [ ] Tests cover major functionality
- [ ] Performance impact is minimal

## Support

- **BunkerWeb Documentation:** [docs.bunkerweb.io](https://docs.bunkerweb.io/)
- **Plugin Development:** [Plugin Documentation](https://docs.bunkerweb.io/latest/plugins/)
- **Community Support:** [Discord Server](https://bunkerity.discord.com/)
- **Issues:** Create an issue in this repository

## Resources

- [BunkerWeb Official Repository](https://github.com/bunkerity/bunkerweb)
- [BunkerWeb Plugins Repository](https://github.com/bunkerity/bunkerweb-plugins)
- [NGINX Lua Module Documentation](https://github.com/openresty/lua-nginx-module)
- [ModSecurity Rule Writing](https://coreruleset.org/docs/)

## Environment Variables Reference

All plugins use the `PLUGIN_` prefix for environment variables:

| Pattern | Description | Example |
|---------|-------------|---------|
| `USE_PLUGIN_NAME` | Enable/disable plugin | `USE_PLUGIN_MYPLUGIN=yes` |
| `PLUGIN_NAME_SETTING` | Plugin-specific setting | `PLUGIN_MYPLUGIN_TIMEOUT=30` |
| `PLUGIN_NAME_LOG_LEVEL` | Plugin log level | `PLUGIN_MYPLUGIN_LOG_LEVEL=INFO` |

### Multisite Configuration

```bash
# Global settings
USE_PLUGIN_MYPLUGIN=yes
PLUGIN_MYPLUGIN_SETTING=global_value

# Per-service settings
app1.example.com_PLUGIN_MYPLUGIN_SETTING=app1_value
app2.example.com_PLUGIN_MYPLUGIN_SETTING=app2_value
```

---

**Note:** This project is designed to work with BunkerWeb 1.6.0+. For older versions, some features may not be available.
EOF
}

# Generate comprehensive documentation
generate_readme() {
    local plugin_dir="$1"
    local plugin_name="$2"
    local plugin_name_upper=$(echo "$plugin_name" | tr '[:lower:]' '[:upper:]')
    
    cat > "$plugin_dir/README.md" << EOF
# $plugin_name Plugin for BunkerWeb

$DESCRIPTION

## Features

- **Core Integration**: Seamlessly integrates with BunkerWeb's NGINX Lua module
- **Multisite Support**: Built-in support for global and per-service configurations
- **Configurable Settings**: Multiple configuration options with validation
- **Performance Monitoring**: Built-in metrics and health checks$([ "$WITH_UI" = "yes" ] && echo "
- **Web UI**: User-friendly configuration interface")$([ "$WITH_JOBS" = "yes" ] && echo "
- **Scheduled Jobs**: Automated maintenance and data processing")$([ "$WITH_CONFIGS" = "yes" ] && echo "
- **Custom NGINX Configs**: Flexible NGINX configuration templates")$([ "$WITH_TEMPLATES" = "yes" ] && echo "
- **Configuration Templates**: Pre-defined configuration templates")
- **Stream Support**: $(echo "$STREAM_MODE" | tr '[:lower:]' '[:upper:]') support for TCP/UDP protocols
- **Security Rules**: Integrated ModSecurity rules for protection
- **Flexible Context**: Multisite context allows both global and service-specific settings

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

## Configuration

### Multisite Context

All plugin settings use **multisite** context by default, which means:
- Settings can be configured globally or per-service
- Per-service settings override global settings  
- Perfect for environments with multiple applications
- Supports both single-site and multi-site deployments

**Global Configuration:**
```bash
USE_PLUGIN_${plugin_name_upper}=yes
PLUGIN_${plugin_name_upper}_SETTING=global_value
```

**Per-Service Configuration:**
```bash
# For service: myapp.example.com
myapp.example.com_USE_PLUGIN_${plugin_name_upper}=yes
myapp.example.com_PLUGIN_${plugin_name_upper}_SETTING=service_specific_value
```

### Multisite Best Practices

1. **Global Defaults**: Set reasonable global defaults for common settings
2. **Service Overrides**: Override only specific settings per service as needed
3. **Consistent Naming**: Use consistent service names across all plugin settings
4. **Environment Separation**: Use different configurations for dev/staging/prod
5. **Security Levels**: Apply stricter settings to production services

**Example Multisite Strategy:**
```bash
# Global defaults (permissive for development)
USE_PLUGIN_${plugin_name_upper}=yes
PLUGIN_${plugin_name_upper}_SETTING=development_default
PLUGIN_${plugin_name_upper}_TIMEOUT=30
PLUGIN_${plugin_name_upper}_LOG_LEVEL=DEBUG

# Production service (strict settings)
prod.example.com_PLUGIN_${plugin_name_upper}_SETTING=production_strict
prod.example.com_PLUGIN_${plugin_name_upper}_TIMEOUT=5
prod.example.com_PLUGIN_${plugin_name_upper}_LOG_LEVEL=WARN

# API service (custom timeout)
api.example.com_PLUGIN_${plugin_name_upper}_TIMEOUT=60
api.example.com_PLUGIN_${plugin_name_upper}_SETTING=api_optimized
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| \`USE_PLUGIN_${plugin_name_upper}\` | \`no\` | Enable or disable the plugin |
| \`PLUGIN_${plugin_name_upper}_SETTING\` | \`default_value\` | Main plugin configuration setting |
| \`PLUGIN_${plugin_name_upper}_TIMEOUT\` | \`5\` | Timeout for plugin operations (1-300 seconds) |
| \`PLUGIN_${plugin_name_upper}_LOG_LEVEL\` | \`DEBUG\` | Log verbosity (DEBUG, INFO, WARN, ERROR) |

### Docker Compose Example

**Single Site:**
\`\`\`yaml
version: '3.8'

services:
  bunkerweb:
    image: bunkerity/bunkerweb:latest
    environment:
      # Global plugin configuration
      - USE_PLUGIN_${plugin_name_upper}=yes
      - PLUGIN_${plugin_name_upper}_SETTING=custom_value
      - PLUGIN_${plugin_name_upper}_TIMEOUT=10
      - PLUGIN_${plugin_name_upper}_LOG_LEVEL=DEBUG
    volumes:
      - ./bw-data:/data
    networks:
      - bw-universe
      - bw-services

  bw-scheduler:
    image: bunkerity/bunkerweb-scheduler:latest
    environment:
      # Same configuration as bunkerweb
      - USE_PLUGIN_${plugin_name_upper}=yes
      - PLUGIN_${plugin_name_upper}_SETTING=custom_value
      - PLUGIN_${plugin_name_upper}_TIMEOUT=10
      - PLUGIN_${plugin_name_upper}_LOG_LEVEL=DEBUG
    volumes:
      - ./bw-data:/data
    networks:
      - bw-universe

networks:
  bw-universe:
    driver: bridge
  bw-services:
    driver: bridge
\`\`\`

**Multisite Configuration:**
\`\`\`yaml
version: '3.8'

services:
  bunkerweb:
    image: bunkerity/bunkerweb:latest
    environment:
      # Enable multisite mode
      - MULTISITE=yes
      
      # Global plugin settings (fallback for all sites)
      - USE_PLUGIN_${plugin_name_upper}=yes
      - PLUGIN_${plugin_name_upper}_SETTING=global_default
      - PLUGIN_${plugin_name_upper}_LOG_LEVEL=DEBUG
      
      # Site-specific settings
      - app1.example.com_USE_PLUGIN_${plugin_name_upper}=yes
      - app1.example.com_PLUGIN_${plugin_name_upper}_SETTING=app1_config
      - app1.example.com_PLUGIN_${plugin_name_upper}_TIMEOUT=15
      
      - app2.example.com_USE_PLUGIN_${plugin_name_upper}=yes  
      - app2.example.com_PLUGIN_${plugin_name_upper}_SETTING=app2_config
      - app2.example.com_PLUGIN_${plugin_name_upper}_TIMEOUT=30
    volumes:
      - ./bw-data:/data
    networks:
      - bw-universe
      - bw-services

  bw-scheduler:
    image: bunkerity/bunkerweb-scheduler:latest
    environment:
      # Mirror the multisite configuration
      - MULTISITE=yes
      - USE_PLUGIN_${plugin_name_upper}=yes
      - PLUGIN_${plugin_name_upper}_SETTING=global_default
      - PLUGIN_${plugin_name_upper}_LOG_LEVEL=DEBUG
      - app1.example.com_USE_PLUGIN_${plugin_name_upper}=yes
      - app1.example.com_PLUGIN_${plugin_name_upper}_SETTING=app1_config
      - app1.example.com_PLUGIN_${plugin_name_upper}_TIMEOUT=15
      - app2.example.com_USE_PLUGIN_${plugin_name_upper}=yes
      - app2.example.com_PLUGIN_${plugin_name_upper}_SETTING=app2_config
      - app2.example.com_PLUGIN_${plugin_name_upper}_TIMEOUT=30
    volumes:
      - ./bw-data:/data
    networks:
      - bw-universe

networks:
  bw-universe:
    driver: bridge
  bw-services:
    driver: bridge
\`\`\`

### Kubernetes Examples

**Single Service:**
\`\`\`yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: my-app-ingress
  annotations:
    bunkerweb.io/USE_PLUGIN_${plugin_name_upper}: "yes"
    bunkerweb.io/PLUGIN_${plugin_name_upper}_SETTING: "kubernetes_value"
    bunkerweb.io/PLUGIN_${plugin_name_upper}_TIMEOUT: "15"
    bunkerweb.io/PLUGIN_${plugin_name_upper}_LOG_LEVEL: "DEBUG"
spec:
  rules:
  - host: myapp.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: my-app-service
            port:
              number: 80
\`\`\`

**Multiple Services with Different Configurations:**
\`\`\`yaml
# Service 1 - Production App
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: prod-app-ingress
  annotations:
    bunkerweb.io/USE_PLUGIN_${plugin_name_upper}: "yes"
    bunkerweb.io/PLUGIN_${plugin_name_upper}_SETTING: "production_strict"
    bunkerweb.io/PLUGIN_${plugin_name_upper}_TIMEOUT: "5"
    bunkerweb.io/PLUGIN_${plugin_name_upper}_LOG_LEVEL: "WARN"
spec:
  rules:
  - host: prod.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: prod-app-service
            port:
              number: 80

---
# Service 2 - Development App  
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: dev-app-ingress
  annotations:
    bunkerweb.io/USE_PLUGIN_${plugin_name_upper}: "yes"
    bunkerweb.io/PLUGIN_${plugin_name_upper}_SETTING: "development_permissive"
    bunkerweb.io/PLUGIN_${plugin_name_upper}_TIMEOUT: "30"
    bunkerweb.io/PLUGIN_${plugin_name_upper}_LOG_LEVEL: "DEBUG"
spec:
  rules:
  - host: dev.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: dev-app-service
            port:
              number: 80
\`\`\`

## Usage

### Plugin Endpoints

Once enabled, the plugin provides several endpoints:

- \`GET /$plugin_name\` - Plugin status and configuration
- \`GET /$plugin_name/status\` - Health check endpoint
- \`GET /$plugin_name/metrics\` - Prometheus-style metrics

### Example API Calls

\`\`\`bash
# Check plugin status
curl https://your-domain.com/$plugin_name/status

# Get plugin metrics
curl https://your-domain.com/$plugin_name/metrics

# Get detailed plugin information
curl https://your-domain.com/$plugin_name
\`\`\`$([ "$WITH_UI" = "yes" ] && echo "

### Web UI

Access the plugin configuration interface at:
\`https://your-bunkerweb-ui.com/plugins/$plugin_name\`

The web UI provides:
- Real-time plugin status
- Configuration management
- Statistics dashboard
- Health monitoring")$([ "$WITH_JOBS" = "yes" ] && echo "

### Scheduled Jobs

The plugin includes automated maintenance jobs that run daily:

- **Data Cleanup**: Removes old log files and temporary data
- **Statistics Processing**: Aggregates request data and generates reports
- **Health Checks**: Validates plugin configuration and system health
- **Metrics Updates**: Updates runtime statistics and performance metrics

**Available Job Frequencies:**
- \`hour\` - Run every hour
- \`daily\` - Run once per day (default)
- \`weekly\` - Run once per week
- \`monthly\` - Run once per month

To change the job frequency, edit the \`every\` field in \`plugin.json\`:
\`\`\`json
"jobs": [
    {
        "name": "myplugin-job",
        "file": "myplugin-job.py",
        "every": "hour"
    }
]
\`\`\`

Job logs are available in: \`/var/log/bunkerweb/$plugin_name-job.log\`")

## File Structure

\`\`\`
$plugin_name/
├── plugin.json                    # Plugin metadata and settings
├── $plugin_name.lua              # Main Lua execution file
├── README.md                      # This documentation$([ "$WITH_UI" = "yes" ] && echo "
├── ui/                            # Web UI components
│   ├── actions.py                 # Flask request handlers
│   ├── template.html              # Web interface template
│   ├── hooks.py                   # Flask lifecycle hooks
│   ├── blueprints/               # Custom Flask blueprints
│   └── templates/                # Additional UI templates")$([ "$WITH_JOBS" = "yes" ] && echo "
├── jobs/                          # Scheduled maintenance jobs
│   └── $plugin_name-job.py       # Main job scheduler script")$([ "$WITH_CONFIGS" = "yes" ] && echo "
├── confs/                         # NGINX configuration templates
│   ├── server-http/              # Server-level HTTP configurations
│   ├── http/                     # HTTP-level configurations
│   ├── default-server-http/      # Default server configurations
│   ├── modsec/                   # ModSecurity rules
│   ├── modsec-crs/              # ModSecurity CRS rules
│   ├── stream/                   # Stream-level configurations
│   └── server-stream/            # Server-level stream configurations")$([ "$WITH_TEMPLATES" = "yes" ] && echo "
└── templates/                     # Configuration templates
    ├── $plugin_name-template.json    # Main template
    ├── $plugin_name-dev.json         # Development template
    ├── $plugin_name-prod.json        # Production template
    └── $plugin_name-template/        # Template with custom configs
        └── configs/
            └── server-http/
                └── custom-endpoint.conf")
\`\`\`

## Development

### Modifying the Plugin

1. **Core Logic**: Edit \`$plugin_name.lua\` for main functionality
2. **Settings**: Update \`plugin.json\` for new configuration options
   - All settings use \`"context": "multisite"\` for maximum flexibility
   - Add new settings following the same pattern
3. **Documentation**: Update this README.md with your changes$([ "$WITH_UI" = "yes" ] && echo "
4. **Web Interface**: Modify files in \`ui/\` directory for UI changes")$([ "$WITH_JOBS" = "yes" ] && echo "
5. **Scheduled Tasks**: Update \`jobs/$plugin_name-job.py\` for job modifications
   - Change frequency in \`plugin.json\` (hour, daily, weekly, monthly)
   - Modify job logic for different execution patterns")$([ "$WITH_CONFIGS" = "yes" ] && echo "
6. **NGINX Configs**: Modify templates in \`confs/\` directory")

### Testing

\`\`\`bash
# Test plugin syntax
nginx -t

# Check BunkerWeb logs
tail -f /var/log/bunkerweb/error.log

# Test plugin endpoints
curl -I https://your-domain.com/$plugin_name/status
\`\`\`

### Debugging

1. **Enable debug logging (already enabled by default):**
   \`\`\`bash
   PLUGIN_${plugin_name_upper}_LOG_LEVEL=DEBUG
   \`\`\`

2. **Check plugin-specific logs:**
   \`\`\`bash
   grep "$plugin_name" /var/log/bunkerweb/error.log
   \`\`\`$([ "$WITH_JOBS" = "yes" ] && echo "

3. **Monitor job execution:**
   \`\`\`bash
   tail -f /var/log/bunkerweb/$plugin_name-job.log
   \`\`\`")

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
   - Adjust \`${plugin_name_upper}_TIMEOUT\` setting
   - Monitor system resources
   - Check for excessive logging$([ "$WITH_JOBS" = "yes" ] && echo "

4. **Job execution failures:**
   - Check job log file for errors
   - Verify file system permissions
   - Ensure required directories exist")

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

create_docs(){
mkdir -p cp "$plugin_dir"/docs
cp template_diagram.drawio "$plugin_dir"/docs
cp template_diagram.svg "$plugin_dir"/docs

}

# Main plugin creation function
create_plugin() {
    local plugin_name="$1"
    local output_dir="$2"
    local plugin_dir="$output_dir/$plugin_name"
    
    echo "Creating BunkerWeb plugin: $plugin_name"
    echo "Output directory: $plugin_dir"
    echo "Description: $DESCRIPTION"
    echo "Version: $VERSION"
    echo "Order: $ORDER"
    echo "Stream mode: $STREAM_MODE"
    echo "Context: multisite (supports global and per-service configuration)"
    
    if [ -d "$plugin_dir" ]; then
        echo "Warning: Directory $plugin_dir already exists"
        read -p "Do you want to continue and overwrite? (y/N): " -r
        if [ "$REPLY" != "y" ] && [ "$REPLY" != "Y" ]; then
            echo "Aborted"
            return 1
        fi
        rm -rf "$plugin_dir"
    fi
    
    echo "Creating directory structure..."
    create_directory_structure "$plugin_dir"
    create_docs
    
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
    # need_fix -> runs another shell
    echo " # need_fix -> runs another shell"
    # generate_readme "$plugin_dir" "$plugin_name"
    
    project_readme_existed="no"
    if [ -f "$plugin_dir/README.md" ]; then
        project_readme_existed="yes"
    fi
    generate_project_readme "$plugin_dir"
    
    echo ""
    echo "Plugin structure created successfully!"
    echo ""
    echo "Directory: $plugin_dir"
    echo "Files created:"
    find "$plugin_dir" -type f | sort | sed 's/^/  /'
    echo ""
    if [ "$project_readme_existed" = "no" ]; then
        echo "Project README.md template created at: $plugin_dir/README.md"
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

# Parse command line arguments
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

# Validate required arguments
if [ -z "$PLUGIN_NAME" ]; then
    echo "Error: Plugin name is required" >&2
    show_usage >&2
    exit 1
fi

if [ -z "$DESCRIPTION" ]; then
    echo "Error: Plugin description is required (use -d or --description)" >&2
    exit 1
fi

# Validate plugin name
if ! validate_plugin_name "$PLUGIN_NAME"; then
    exit 1
fi

# Validate output directory
if [ ! -d "$OUTPUT_DIR" ]; then
    echo "Error: Output directory does not exist: $OUTPUT_DIR" >&2
    exit 1
fi

# Validate order
if ! echo "$ORDER" | grep -q '^[0-9]\+$' || [ "$ORDER" -lt 1 ] || [ "$ORDER" -gt 999 ]; then
    echo "Error: Order must be a number between 1 and 999" >&2
    exit 1
fi

# Create the plugin
create_plugin "$PLUGIN_NAME" "$OUTPUT_DIR"