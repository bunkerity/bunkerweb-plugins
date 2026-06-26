#!/bin/bash

# Requires bash and GNU coreutils (mkdir, cat, sed, grep, tr, awk, find).
set -eu

# Colors — suppressed when neither stdout/stderr is a TTY, or NO_COLOR is set
# (https://no-color.org/).
if { [ ! -t 1 ] && [ ! -t 2 ]; } || [ -n "${NO_COLOR:-}" ]; then
    RED='' GREEN='' YELLOW='' BLUE='' BOLD='' NC=''
else
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    BOLD='\033[1m'
    NC='\033[0m'
fi

print_info()    { echo -e "${GREEN}[INFO]${NC} $1"; }
print_step()    { echo -e "${BLUE}[STEP]${NC} $1"; }
print_success() { echo -e "${GREEN}[OK]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[WARNING]${NC} $1" >&2; }
print_error()   { echo -e "${RED}[ERROR]${NC} $1" >&2; }

show_usage() {
    cat << 'EOF'
Usage: ./create_bunkerweb_plugin.sh [OPTIONS] PLUGIN_NAME

Create a new BunkerWeb plugin template with proper structure and files.

OPTIONS:
    -h, --help              Show this help message
    -d, --description TEXT  Plugin description (required)
    -v, --version VERSION   Plugin version (default: 1.0.0)
    -o, --output DIR        Output directory (default: parent directory)
    --stream MODE           Stream support: no|partial|yes (default: partial)
    --with-ui               Include web UI components
    --with-jobs             Include job scheduler components (day frequency)
    --with-configs          Include NGINX configuration templates
    --with-templates        Include custom configuration templates

EXAMPLES:
    ./create_bunkerweb_plugin.sh -d "Rate limiting plugin" ratelimit
    ./create_bunkerweb_plugin.sh -d "Custom WAF rules" -v "2.1.0" --with-ui customwaf
    ./create_bunkerweb_plugin.sh -d "Log analyzer" --with-jobs loganalyzer
    ./create_bunkerweb_plugin.sh -d "Security monitor" --with-jobs --with-ui monitor

NOTE:
- Script creates plugins in parent directory by default (assumes run from templates/)
- Creates project README.md template if it doesn't exist
- Jobs default to daily frequency. Edit plugin.json to change to minute/hour/day/week/once.
EOF
}

# JSON-escape a string for safe interpolation into generated plugin.json
# (handles backslash, double-quote and control characters).
json_escape() {
    printf '%s' "$1" | python3 -c 'import json,sys; sys.stdout.write(json.dumps(sys.stdin.read())[1:-1])'
}

# Title-case a plugin name (split on - / _), portably (no GNU sed \U / \|).
title_case() {
    printf '%s' "$1" | awk '
        BEGIN { FS = "[-_]"; OFS = "" }
        {
            for (i = 1; i <= NF; i++) {
                $i = toupper(substr($i, 1, 1)) substr($i, 2)
            }
            print
        }'
}

validate_plugin_name() {
    local name="$1"

    if [ -z "$name" ]; then
        print_error "Plugin name is required"
        return 1
    fi

    if echo "$name" | grep -q '[^a-zA-Z0-9_-]'; then
        print_error "Plugin name must contain only alphanumeric characters, hyphens, and underscores"
        return 1
    fi

    if [ "${#name}" -gt 50 ]; then
        print_error "Plugin name must be 50 characters or less"
        return 1
    fi

    return 0
}

create_directory_structure() {
    local plugin_dir="$1"

    mkdir -p "$plugin_dir"

    if [ "$WITH_UI" = "yes" ]; then
        mkdir -p "$plugin_dir/ui"
    fi

    if [ "$WITH_JOBS" = "yes" ]; then
        mkdir -p "$plugin_dir/jobs"
    fi

    if [ "$WITH_CONFIGS" = "yes" ]; then
        mkdir -p "$plugin_dir/confs/server-http"
        mkdir -p "$plugin_dir/confs/http"
        mkdir -p "$plugin_dir/confs/default-server-http"
        # Stream configs only make sense when the plugin supports stream mode.
        if [ "$STREAM_MODE" != "no" ]; then
            mkdir -p "$plugin_dir/confs/stream"
            mkdir -p "$plugin_dir/confs/server-stream"
        fi
    fi

    if [ "$WITH_TEMPLATES" = "yes" ]; then
        mkdir -p "$plugin_dir/templates"
    fi
}

create_docs() {
    local plugin_dir="$1"

    mkdir -p "$plugin_dir/docs"

    if [ -f "template_diagram.mmd" ]; then
        cp "template_diagram.mmd" "$plugin_dir/docs/diagram.mmd"
    fi
}

generate_plugin_json() {
    local plugin_dir="$1"
    local plugin_name="$2"
    local plugin_name_upper
    plugin_name_upper=$(echo "$plugin_name" | tr '[:lower:]-' '[:upper:]_')

    cat > "$plugin_dir/plugin.json" << EOF
{
    "id": "$plugin_name",
    "name": "$(title_case "$plugin_name")",
    "description": "$(json_escape "$DESCRIPTION")",
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
        },
        "PLUGIN_${plugin_name_upper}_TIMEOUT": {
            "context": "multisite",
            "default": "5",
            "help": "Timeout (in seconds) for $plugin_name plugin operations (1-300).",
            "id": "plugin-${plugin_name}-timeout",
            "label": "${plugin_name} Timeout",
            "regex": "^([1-9][0-9]?|[12][0-9]{2}|300)$",
            "type": "text"
        },
        "PLUGIN_${plugin_name_upper}_LOG_LEVEL": {
            "context": "multisite",
            "default": "INFO",
            "help": "Log verbosity for the $plugin_name plugin.",
            "id": "plugin-${plugin_name}-log-level",
            "label": "${plugin_name} Log Level",
            "regex": "^(DEBUG|INFO|WARN|ERROR)$",
            "select": ["DEBUG", "INFO", "WARN", "ERROR"],
            "type": "select"
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
    local plugin_name_upper
    plugin_name_upper=$(echo "$plugin_name" | tr '[:lower:]-' '[:upper:]_')
    # Lua identifiers cannot contain hyphens; derive a safe variable name while
    # keeping the original plugin id for the BW-facing strings.
    local plugin_ident
    plugin_ident=$(echo "$plugin_name" | tr '-' '_')
    local lua_file="$plugin_dir/$plugin_name.lua"

    cat > "$lua_file" << 'EOF'
local class = require "middleclass"
local plugin = require "bunkerweb.plugin"

local PLUGIN_NAME_LOWER = class("PLUGIN_ID", plugin)

function PLUGIN_NAME_LOWER:initialize(ctx)
    plugin.initialize(self, "PLUGIN_ID", ctx)
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
EOF

    # Stream-context hooks only make sense when the plugin supports stream mode.
    if [ "$STREAM_MODE" != "no" ]; then
        cat >> "$lua_file" << 'EOF'

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
EOF
    fi

    cat >> "$lua_file" << 'EOF'

return PLUGIN_NAME_LOWER
EOF

    sed -i.bak "s|PLUGIN_NAME_LOWER|${plugin_ident}|g" "$lua_file"
    sed -i.bak "s|PLUGIN_ID|${plugin_name}|g" "$lua_file"
    sed -i.bak "s|USE_PLUGIN_NAME_UPPER|USE_${plugin_name_upper}|g" "$lua_file"
    rm -f "$lua_file.bak"
}

generate_ui_components() {
    local plugin_dir="$1"
    local plugin_name="$2"
    local plugin_name_upper
    plugin_name_upper=$(echo "$plugin_name" | tr '[:lower:]-' '[:upper:]_')
    # Python function names cannot contain hyphens; for hyphen-free ids this is
    # identical to the id (which is what BunkerWeb looks up for the page).
    local plugin_ident
    plugin_ident=$(echo "$plugin_name" | tr '-' '_')

    # BunkerWeb UI plugin contract: pre_render(**kwargs) returns card data for
    # the plugin's UI page, and BunkerWeb resolves the page handler via
    # getattr(actions, "<id>"). See clamav/ui/actions.py for the reference.
    cat > "$plugin_dir/ui/actions.py" << EOF
from logging import getLogger
from traceback import format_exc


def pre_render(**kwargs):
    logger = getLogger("UI")
    ret = {
        "ping_status": {
            "title": "${plugin_name_upper} STATUS",
            "value": "error",
            "col-size": "col-12 col-md-6",
            "card-classes": "h-100",
        },
    }
    try:
        ping_data = kwargs["bw_instances_utils"].get_ping("$plugin_name")
        ret["ping_status"]["value"] = ping_data["status"]
    except BaseException as e:
        logger.debug(format_exc())
        logger.error(f"Failed to get $plugin_name ping: {e}")
        ret["error"] = str(e)

    return ret


def $plugin_ident(**kwargs):
    pass
EOF

    # BunkerWeb looks the page handler up by the raw id via getattr(actions, "<id>").
    # When the id contains a hyphen it is not a valid Python function name, so
    # expose the handler under the exact id as well.
    if [ "$plugin_name" != "$plugin_ident" ]; then
        cat >> "$plugin_dir/ui/actions.py" << EOF


globals()["$plugin_name"] = $plugin_ident
EOF
    fi
}

generate_job_files() {
    local plugin_dir="$1"
    local plugin_name="$2"
    local plugin_name_upper
    plugin_name_upper=$(echo "$plugin_name" | tr '[:lower:]-' '[:upper:]_')

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
        log_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        logging.basicConfig(level=logging.INFO, format=log_format)
        return logging.getLogger(f"{self.plugin_name}-job")

    def load_configuration(self):
        """
        Load plugin configuration from environment variables
        """
        return {
            "enabled": os.getenv("USE_${plugin_name_upper}", "no") == "yes",
            "setting": os.getenv("PLUGIN_${plugin_name_upper}_SETTING", "default_value"),
            "timeout": int(os.getenv("PLUGIN_${plugin_name_upper}_TIMEOUT", "5")),
            "log_level": os.getenv("PLUGIN_${plugin_name_upper}_LOG_LEVEL", "INFO"),
        }

    def run(self):
        """
        Main job execution method
        """
        try:
            self.logger.info(f"Starting {self.plugin_name} job execution")

            if not self.config["enabled"]:
                self.logger.info("Plugin disabled, skipping job execution")
                return True

            cleanup_success = self.cleanup_old_data()
            processing_success = self.process_data()
            health_success = self.perform_health_checks()

            all_success = cleanup_success and processing_success and health_success

            if all_success:
                self.logger.info(f"{self.plugin_name} job completed successfully")
            else:
                self.logger.warning(
                    f"{self.plugin_name} job completed with some failures"
                )

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

            # Only ever delete from this plugin's own private directory.
            # Never touch shared BunkerWeb dirs (e.g. /var/log/bunkerweb,
            # /tmp/bunkerweb) — other plugins and the core write there too.
            cleanup_paths = [f"/tmp/{self.plugin_name}/"]

            cutoff_date = datetime.now() - timedelta(days=7)
            files_removed = 0

            for cleanup_path in cleanup_paths:
                if os.path.exists(cleanup_path):
                    for file_path in Path(cleanup_path).glob("**/*"):
                        if file_path.is_file():
                            file_modified = datetime.fromtimestamp(
                                file_path.stat().st_mtime
                            )
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
            if not self.config["enabled"]:
                self.logger.info("Plugin disabled, skipping data processing")
                return True

            start_time = time.time()

            processed_requests = self.process_request_logs()

            stats = self.generate_statistics(processed_requests)

            self.save_processed_data(stats)

            processing_time = time.time() - start_time
            self.logger.info(
                f"Data processing completed in {processing_time:.2f} seconds. "
                f"Processed {len(processed_requests)} requests"
            )
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
        log_files = list(Path("/var/log/bunkerweb/").glob(log_pattern))

        for log_file in log_files:
            try:
                with open(log_file, "r") as f:
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
                    "timestamp": parts[0] + " " + parts[1],
                    "level": parts[3],
                    "message": " ".join(parts[5:]),
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
            level = request.get("level", "UNKNOWN")
            level_counts[level] = level_counts.get(level, 0) + 1

        return {
            "total_requests": total_requests,
            "level_distribution": level_counts,
            "generated_at": datetime.now().isoformat(),
            "plugin_version": self.version,
        }

    def save_processed_data(self, stats):
        """
        Save processed statistics data
        """
        stats_file = f"/var/log/bunkerweb/{self.plugin_name}-stats.json"

        try:
            with open(stats_file, "w") as f:
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
                self.check_log_file_permissions(),
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
            required_configs = ["setting", "timeout", "log_level"]

            for config in required_configs:
                if config not in self.config:
                    self.logger.error(f"Missing required configuration: {config}")
                    return False

            if not (1 <= self.config["timeout"] <= 300):
                self.logger.error(f"Invalid timeout value: {self.config['timeout']}")
                return False

            valid_log_levels = ["DEBUG", "INFO", "WARN", "ERROR"]
            if self.config["log_level"] not in valid_log_levels:
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
            disk_usage = psutil.disk_usage("/").percent
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

            self.logger.info(
                f"System resources OK - Memory: {memory_usage}%, "
                f"Disk: {disk_usage}%, CPU: {cpu_usage}%"
            )
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
                "/var/log/bunkerweb/error.log",
                f"/var/log/bunkerweb/{self.plugin_name}.log",
            ]

            for log_file in log_files:
                if os.path.exists(log_file):
                    if not os.access(log_file, os.R_OK | os.W_OK):
                        self.logger.error(
                            f"Insufficient permissions for log file: {log_file}"
                        )
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
    plugin_name_upper=$(echo "$plugin_name" | tr '[:lower:]-' '[:upper:]_')
    # nginx identifiers (log_format / lua_shared_dict names) cannot contain
    # hyphens; use a safe form while keeping the original id for URL paths.
    local plugin_ident
    plugin_ident=$(echo "$plugin_name" | tr '-' '_')

    cat > "$plugin_dir/confs/server-http/$plugin_name.conf" << EOF
# $plugin_name Plugin - Server HTTP Configuration
#
# Server-level (per-vhost) NGINX directives for the $plugin_name plugin. This
# file is included inside each enabled server block.
#
# Example: a custom location served by the plugin. Left commented so the scaffold
# ships no live, unauthenticated endpoint by default — uncomment and adapt, and
# add your own access control (do not expose anything sensitive).
#
# {% if USE_${plugin_name_upper} == "yes" %}
#
# location /$plugin_name/example {
#     access_by_lua_block {
#         ngx.header.content_type = "application/json"
#         ngx.say('{"plugin":"$plugin_name","status":"ok"}')
#         ngx.exit(200)
#     }
# }
#
# {% endif %}
EOF

    cat > "$plugin_dir/confs/http/$plugin_name.conf" << EOF
# $plugin_name Plugin - HTTP Configuration

{% if USE_${plugin_name_upper} == "yes" %}

# Custom log format for plugin
log_format ${plugin_ident}_custom
    '\$remote_addr - \$remote_user [\$time_local] '
    '"\$request" \$status \$body_bytes_sent '
    '"\$http_referer" "\$http_user_agent" '
    '${plugin_name}_setting="{{ PLUGIN_${plugin_name_upper}_SETTING }}" '
    '${plugin_name}_timeout={{ PLUGIN_${plugin_name_upper}_TIMEOUT }} '
    'request_time=\$request_time '
    'upstream_response_time=\$upstream_response_time';

# Shared memory zone for plugin data
lua_shared_dict plugin_${plugin_ident}_cache 10m;
lua_shared_dict plugin_${plugin_ident}_stats 5m;

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

    # Stream configs only when the plugin supports stream mode.
    if [ "$STREAM_MODE" != "no" ]; then
        cat > "$plugin_dir/confs/stream/$plugin_name.conf" << EOF
# $plugin_name Plugin - Stream Configuration

{% if USE_${plugin_name_upper} == "yes" and LISTEN_STREAM == "yes" %}

# Shared memory for stream plugin data
lua_shared_dict stream_plugin_${plugin_ident}_cache 5m;

# Log format for stream connections
log_format ${plugin_ident}_stream
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
    fi
}

generate_custom_templates() {
    local plugin_dir="$1"
    local plugin_name="$2"
    local plugin_name_upper
    plugin_name_upper=$(echo "$plugin_name" | tr '[:lower:]-' '[:upper:]_')

    # BunkerWeb template schema: a top-level "settings" map of value overrides,
    # plus "steps" that group setting NAMES under a title/subtitle for the UI
    # wizard (both "title" and "subtitle" are required). See the core "templates"
    # plugin for the reference format.
    write_template() {
        # $1=file  $2=name  $3=setting value  $4=timeout  $5=log level
        cat > "$1" << EOF
{
    "name": "$2",
    "settings": {
        "USE_${plugin_name_upper}": "yes",
        "PLUGIN_${plugin_name_upper}_SETTING": "$3",
        "PLUGIN_${plugin_name_upper}_TIMEOUT": "$4",
        "PLUGIN_${plugin_name_upper}_LOG_LEVEL": "$5"
    },
    "steps": [
        {
            "title": "$plugin_name configuration",
            "subtitle": "Configure the $plugin_name plugin",
            "settings": [
                "USE_${plugin_name_upper}",
                "PLUGIN_${plugin_name_upper}_SETTING",
                "PLUGIN_${plugin_name_upper}_TIMEOUT",
                "PLUGIN_${plugin_name_upper}_LOG_LEVEL"
            ]
        }
    ]
}
EOF
    }

    write_template "$plugin_dir/templates/$plugin_name-template.json" "$plugin_name default template" "template_value" "10" "INFO"
    write_template "$plugin_dir/templates/$plugin_name-dev.json" "$plugin_name development" "development_mode" "30" "DEBUG"
    write_template "$plugin_dir/templates/$plugin_name-prod.json" "$plugin_name production" "production_mode" "5" "WARN"

    unset -f write_template
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
│   └── actions.py          # BunkerWeb UI hooks (pre_render + page handler)
├── jobs/                    # Scheduled maintenance jobs (optional)
│   └── plugin-name-job.py  # Job scheduler script
├── confs/                   # NGINX configuration templates (optional)
│   ├── server-http/        # Server-level HTTP configurations
│   ├── http/               # HTTP-level configurations
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
   git clone https://github.com/bunkerity/bunkerweb-plugins
   cd bunkerweb-plugins
   ```

2. **Install plugins to BunkerWeb:**

   **For Docker:**
   ```bash
   # Copy plugins to BunkerWeb data directory
   cp -r plugin-name /path/to/bw-data/plugins/

   # Set correct permissions
   chown -R 101:101 /path/to/bw-data/plugins/plugin-name
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
   # Enable plugin (replace MYPLUGIN with the plugin's upper-cased id)
   USE_MYPLUGIN=yes
   PLUGIN_MYPLUGIN_SETTING=your_value
   ```
EOF
}

generate_readme() {
    local plugin_dir="$1"
    local plugin_name="$2"
    local plugin_name_upper
    plugin_name_upper=$(echo "$plugin_name" | tr '[:lower:]-' '[:upper:]_')

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

\`\`\`mermaid
$(cat "$plugin_dir/docs/diagram.mmd")
\`\`\`

## Features

$features

## Installation

### Docker Integration

1. **Download the plugin:**
   \`\`\`bash
   git clone https://github.com/bunkerity/bunkerweb-plugins && cd bunkerweb-plugins
   \`\`\`

2. **Copy to BunkerWeb plugins directory:**
   \`\`\`bash
   cp -r $plugin_name /path/to/bw-data/plugins/
   \`\`\`

3. **Set correct permissions:**
   \`\`\`bash
   chown -R 101:101 /path/to/bw-data/plugins/$plugin_name
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

    echo -e "${BOLD}Creating BunkerWeb plugin '${plugin_name}'${NC}"
    print_info "Output directory : $plugin_dir"
    print_info "Description      : $DESCRIPTION"
    print_info "Version          : $VERSION"
    print_info "Stream mode      : $STREAM_MODE"
    print_info "Context          : multisite (global and per-service)"
    echo ""

    if [ -d "$plugin_dir" ]; then
        print_warning "Directory $plugin_dir already exists"
        printf "Do you want to continue and overwrite? (y/N): "
        # Name the variable explicitly (POSIX) and tolerate EOF under set -e so
        # non-interactive runs fall through to the safe no-overwrite branch.
        read -r REPLY || REPLY=""
        if [ "$REPLY" != "y" ] && [ "$REPLY" != "Y" ]; then
            print_warning "Aborted — existing directory left untouched"
            return 1
        fi
        rm -rf "$plugin_dir"
    fi

    print_step "Creating directory structure"
    create_directory_structure "$plugin_dir"
    create_docs "$plugin_dir"

    print_step "Generating core files (plugin.json, ${plugin_name}.lua)"
    generate_plugin_json "$plugin_dir" "$plugin_name"
    generate_lua_file "$plugin_dir" "$plugin_name"

    if [ "$WITH_UI" = "yes" ]; then
        print_step "Generating UI components"
        generate_ui_components "$plugin_dir" "$plugin_name"
    fi

    if [ "$WITH_JOBS" = "yes" ]; then
        print_step "Generating job files"
        generate_job_files "$plugin_dir" "$plugin_name"
    fi

    if [ "$WITH_CONFIGS" = "yes" ]; then
        print_step "Generating NGINX configuration templates"
        generate_config_templates "$plugin_dir" "$plugin_name"
    fi

    if [ "$WITH_TEMPLATES" = "yes" ]; then
        print_step "Generating custom templates"
        generate_custom_templates "$plugin_dir" "$plugin_name"
    fi

    print_step "Generating documentation"
    generate_readme "$plugin_dir" "$plugin_name"

    project_readme_existed="no"
    if [ -f "$output_dir/README.md" ]; then
        project_readme_existed="yes"
    fi
    generate_project_readme "$output_dir"

    echo ""
    print_success "Plugin '${plugin_name}' created in $plugin_dir"
    echo ""
    echo -e "${BOLD}Files created:${NC}"
    find "$plugin_dir" -type f | sort | sed 's/^/  /'
    echo ""
    if [ "$project_readme_existed" = "no" ]; then
        print_info "Project README.md template created at: $output_dir/README.md"
        echo ""
    fi
    echo -e "${BOLD}Next steps:${NC}"
    echo "  1. Implement your logic in $plugin_name.lua"
    echo "  2. Adjust settings in plugin.json as needed"
    echo "  3. Update README.md with your plugin's specifics"
    echo "  4. Test the plugin against a BunkerWeb instance"
    echo ""
    echo -e "${BOLD}Install (Docker):${NC}"
    echo "  cp -r $plugin_dir /path/to/bw-data/plugins/ && \\"
    echo "  chown -R 101:101 /path/to/bw-data/plugins/$plugin_name && \\"
    echo "  chmod -R 750 /path/to/bw-data/plugins/$plugin_name"
}

PLUGIN_NAME=""
DESCRIPTION=""
VERSION="1.0.0"
OUTPUT_DIR=".."
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
        [ $# -ge 2 ] || { print_error "$1 requires a value"; exit 1; }
        DESCRIPTION="$2"
        shift 2
    elif [ "$1" = "-v" ] || [ "$1" = "--version" ]; then
        [ $# -ge 2 ] || { print_error "$1 requires a value"; exit 1; }
        VERSION="$2"
        shift 2
    elif [ "$1" = "-o" ] || [ "$1" = "--output" ]; then
        [ $# -ge 2 ] || { print_error "$1 requires a value"; exit 1; }
        OUTPUT_DIR="$2"
        shift 2
    elif [ "$1" = "--stream" ]; then
        [ $# -ge 2 ] || { print_error "$1 requires a value"; exit 1; }
        if [ "$2" = "no" ] || [ "$2" = "partial" ] || [ "$2" = "yes" ]; then
            STREAM_MODE="$2"
        else
            print_error "Invalid stream mode. Use: no, partial, or yes"
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
        print_error "Unknown option: $1"
        show_usage >&2
        exit 1
    else
        if [ -z "$PLUGIN_NAME" ]; then
            PLUGIN_NAME="$1"
        else
            print_error "Multiple plugin names specified"
            exit 1
        fi
        shift
    fi
done

if [ -z "$PLUGIN_NAME" ]; then
    print_error "Plugin name is required"
    show_usage >&2
    exit 1
fi

if [ -z "$DESCRIPTION" ]; then
    print_error "Plugin description is required (use -d or --description)"
    exit 1
fi

if ! validate_plugin_name "$PLUGIN_NAME"; then
    exit 1
fi

if [ ! -d "$OUTPUT_DIR" ]; then
    print_error "Output directory does not exist: $OUTPUT_DIR"
    exit 1
fi

create_plugin "$PLUGIN_NAME" "$OUTPUT_DIR"
