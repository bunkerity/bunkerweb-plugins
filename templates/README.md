# BunkerWeb Plugin Generator

A comprehensive shell script for generating BunkerWeb plugin templates with complete structure, documentation, and optional components.

## Overview

The `create_bunkerweb_plugin.sh` script automates the creation of BunkerWeb plugins with proper directory structure, configuration files, and comprehensive documentation. It supports generating plugins with various optional components including web UI, scheduled jobs, NGINX configurations, and configuration templates.

## Features

- **Complete Plugin Structure**: Generates all necessary files and directories
- **POSIX Compatible**: Works on any POSIX-compliant shell
- **Multisite Support**: All generated plugins use multisite context by default
- **Optional Components**: Choose what to include in your plugin
- **Comprehensive Documentation**: Auto-generates detailed README files
- **Template Files**: Creates example configurations and templates
- **Validation**: Validates plugin names and parameters
- **Flexible Configuration**: Supports various plugin orders and stream modes

## Requirements

- POSIX-compliant shell (bash, zsh, dash, etc.)
- Basic Unix utilities (mkdir, cat, sed, grep, find, etc.)
- Write permissions in the target directory

## Installation

1. **Download the script:**
   ```bash
   curl -O https://your-repo/create_bunkerweb_plugin.sh
   chmod +x create_bunkerweb_plugin.sh
   ```

2. **Or clone the repository:**
   ```bash
   git clone <your-repo-url>
   cd templates/
   ```

## Usage

### Basic Syntax

```bash
./create_bunkerweb_plugin.sh [OPTIONS] PLUGIN_NAME
```

### Required Parameters

- `PLUGIN_NAME`: Name of the plugin (alphanumeric, hyphens, underscores only)
- `-d, --description TEXT`: Plugin description (required)

### Options

| Option | Description | Default |
|--------|-------------|---------|
| `-h, --help` | Show help message | - |
| `-d, --description TEXT` | Plugin description | Required |
| `-v, --version VERSION` | Plugin version | 1.0.0 |
| `-o, --output DIR` | Output directory | .. (parent directory) |
| `--order NUMBER` | Plugin execution order (1-999) | 256 |
| `--stream MODE` | Stream support: no/partial/yes | partial |
| `--with-ui` | Include web UI components | false |
| `--with-jobs` | Include job scheduler components | false |
| `--with-configs` | Include NGINX configuration templates | false |
| `--with-templates` | Include custom configuration templates | false |

### Examples

#### Basic Plugin
```bash
./create_bunkerweb_plugin.sh -d "Rate limiting plugin" ratelimit
```

#### Full-Featured Plugin
```bash
./create_bunkerweb_plugin.sh \
  -d "Advanced security monitor" \
  -v "2.1.0" \
  --order 10 \
  --stream yes \
  --with-ui \
  --with-jobs \
  --with-configs \
  --with-templates \
  security-monitor
```

#### Web UI Plugin
```bash
./create_bunkerweb_plugin.sh \
  -d "Custom WAF rules with web interface" \
  --with-ui \
  customwaf
```

#### Background Job Plugin
```bash
./create_bunkerweb_plugin.sh \
  -d "Log analyzer with daily processing" \
  --with-jobs \
  --order 500 \
  loganalyzer
```

## Generated Structure

### Basic Plugin Structure
```
plugin-name/
├── plugin.json                 # Plugin metadata and settings
├── plugin-name.lua            # Main Lua execution file
├── README.md                  # Comprehensive documentation
└── docs/                      # Documentation assets
    ├── template_diagram.drawio
    └── template_diagram.svg
```

### With UI Components (`--with-ui`)
```
plugin-name/
├── ui/
│   ├── actions.py             # Flask request handlers
│   ├── template.html          # Web interface template
│   ├── hooks.py               # Flask lifecycle hooks
│   ├── blueprints/           # Custom Flask blueprints
│   └── templates/            # Additional UI templates
```

### With Job Scheduler (`--with-jobs`)
```
plugin-name/
├── jobs/
│   └── plugin-name-job.py     # Scheduled job script (daily by default)
```

### With NGINX Configs (`--with-configs`)
```
plugin-name/
├── confs/
│   ├── server-http/           # Server-level HTTP configurations
│   ├── http/                  # HTTP-level configurations
│   ├── default-server-http/   # Default server configurations
│   ├── modsec/               # ModSecurity rules
│   ├── modsec-crs/          # ModSecurity CRS rules
│   ├── stream/               # Stream-level configurations
│   └── server-stream/        # Server-level stream configurations
```

### With Templates (`--with-templates`)
```
plugin-name/
├── templates/
│   ├── plugin-name-template.json    # Main template
│   ├── plugin-name-dev.json         # Development template
│   ├── plugin-name-prod.json        # Production template
│   └── plugin-name-template/        # Template with custom configs
```

## Plugin Features

### Generated Plugin Capabilities

All generated plugins include:

- **Multisite Context**: Global and per-service configuration support
- **Four NGINX Phases**: init, access, log, preread (stream)
- **Comprehensive Logging**: Configurable log levels with detailed output
- **Settings Validation**: Input validation for all configuration options
- **Health Endpoints**: Status, metrics, and configuration endpoints
- **Error Handling**: Robust error handling and recovery
- **Performance Monitoring**: Built-in timing and metrics collection

### Default Settings

Every plugin generates with these configurable settings:

| Setting | Description | Default | Validation |
|---------|-------------|---------|------------|
| `USE_PLUGIN_NAME` | Enable/disable plugin | no | yes/no |
| `PLUGIN_NAME_SETTING` | Main configuration | default_value | Any string |
| `PLUGIN_NAME_TIMEOUT` | Operation timeout | 5 | 1-300 seconds |
| `PLUGIN_NAME_LOG_LEVEL` | Log verbosity | DEBUG | DEBUG/INFO/WARN/ERROR |

### Multisite Configuration

Generated plugins support both global and per-service configuration:

```bash
# Global configuration
USE_PLUGIN_MYPLUGIN=yes
PLUGIN_MYPLUGIN_SETTING=global_value

# Per-service configuration
app1.example.com_USE_PLUGIN_MYPLUGIN=yes
app1.example.com_PLUGIN_MYPLUGIN_SETTING=service_specific_value
```

## Web UI Components

When using `--with-ui`, the script generates:

- **Flask Integration**: Complete Flask blueprint structure
- **Configuration Interface**: Web-based plugin configuration
- **Real-time Status**: Live plugin status and statistics
- **Form Validation**: Client and server-side validation
- **Responsive Design**: Mobile-friendly interface
- **AJAX Updates**: Dynamic updates without page refresh

## Job Scheduler

When using `--with-jobs`, the script generates:

- **Daily Jobs**: Default daily execution frequency
- **Configurable Frequency**: Easy to change to hourly, weekly, or monthly
- **Data Processing**: Template for log processing and analytics
- **Health Checks**: Automated plugin health validation
- **Cleanup Tasks**: Automated old data cleanup
- **Comprehensive Logging**: Detailed job execution logs

Available job frequencies:
- `hour` - Run every hour
- `daily` - Run once per day (default)
- `weekly` - Run once per week  
- `monthly` - Run once per month

## NGINX Configuration Templates

When using `--with-configs`, the script generates:

### HTTP Configurations
- **server-http**: Server block configurations
- **http**: HTTP block configurations  
- **default-server-http**: Default server configurations

### Security Configurations
- **modsec**: Custom ModSecurity rules
- **modsec-crs**: ModSecurity Core Rule Set configurations

### Stream Configurations
- **stream**: Stream block configurations
- **server-stream**: Stream server configurations

## Configuration Templates

When using `--with-templates`, the script generates:

- **Development Template**: Permissive settings for development
- **Production Template**: Strict settings for production
- **Custom Template**: Template with custom NGINX configurations
- **Template Structure**: Organized template hierarchy

## Stream Support

The `--stream` option configures TCP/UDP protocol support:

- `no`: HTTP only (default for web-focused plugins)
- `partial`: HTTP primary with stream support (recommended)
- `yes`: Full stream support (for TCP/UDP focused plugins)

## Plugin Order

The `--order` option sets plugin execution priority:

- **1-99**: Early execution (authentication, rate limiting)
- **100-199**: Security processing (WAF, filtering)
- **200-299**: Content processing (transformation, caching)
- **300-999**: Late processing (logging, analytics)

Default: 256 (content processing phase)

## Validation Rules

### Plugin Name Validation
- Only alphanumeric characters, hyphens, and underscores
- Maximum 50 characters
- Cannot be empty

### Parameter Validation
- Order: 1-999
- Stream mode: no, partial, or yes
- Output directory must exist
- Description cannot be empty

## Generated Documentation

The script automatically generates:

### Plugin README.md
- Complete installation instructions
- Configuration examples for Docker, Kubernetes
- Usage documentation with API examples
- Development guidelines
- Troubleshooting section
- File structure documentation

### Project README.md (if not exists)
- Project overview and structure
- Plugin development workflow
- Contributing guidelines
- Best practices and standards

## Installation Integration

### Docker Integration
```bash
# Copy plugin to BunkerWeb
cp -r plugin-name /path/to/bw-data/plugins/

# Set permissions
chown -R root:101 /path/to/bw-data/plugins/plugin-name
chmod -R 750 /path/to/bw-data/plugins/plugin-name
```

### Linux Integration
```bash
# Copy plugin to BunkerWeb
cp -r plugin-name /etc/bunkerweb/plugins/

# Set permissions  
chown -R root:nginx /etc/bunkerweb/plugins/plugin-name
chmod -R 750 /etc/bunkerweb/plugins/plugin-name

# Restart BunkerWeb
systemctl restart bunkerweb
```

## Troubleshooting

### Common Issues

1. **Permission Denied**
   ```bash
   chmod +x create_bunkerweb_plugin.sh
   ```

2. **Directory Exists Error**
   - Plugin directory already exists
   - Choose different name or remove existing directory

3. **Invalid Plugin Name**
   - Use only alphanumeric characters, hyphens, underscores
   - Maximum 50 characters

4. **Missing Description**
   - Description is required: use `-d "Your description"`

### Debugging

Run with debug output:
```bash
bash -x create_bunkerweb_plugin.sh -d "Test plugin" testplugin
```

### File Permissions

Ensure the script has execute permissions:
```bash
ls -la create_bunkerweb_plugin.sh
# Should show: -rwxr-xr-x
```

## Examples by Use Case

### Security Plugin
```bash
./create_bunkerweb_plugin.sh \
  -d "Advanced threat detection and blocking" \
  --order 50 \
  --stream partial \
  --with-configs \
  threat-detector
```

### Analytics Plugin
```bash
./create_bunkerweb_plugin.sh \
  -d "Request analytics and reporting" \
  --order 800 \
  --with-jobs \
  --with-ui \
  analytics
```

### Rate Limiting Plugin
```bash
./create_bunkerweb_plugin.sh \
  -d "Intelligent rate limiting with adaptive thresholds" \
  --order 20 \
  --with-configs \
  --with-templates \
  smart-ratelimit
```

### Content Filter Plugin
```bash
./create_bunkerweb_plugin.sh \
  -d "Content filtering and transformation" \
  --order 300 \
  --stream no \
  content-filter
```

## Best Practices

### Plugin Development
1. **Start Simple**: Begin with basic plugin, add components as needed
2. **Use Templates**: Leverage generated templates for consistency
3. **Test Thoroughly**: Test with both single-site and multisite configurations
4. **Document Everything**: Update README.md with your specific functionality
5. **Follow Conventions**: Use generated naming patterns and structure

### Configuration Management
1. **Global Defaults**: Set reasonable global defaults
2. **Service Overrides**: Override only specific settings per service
3. **Environment Separation**: Use different configurations for dev/staging/prod
4. **Security Levels**: Apply stricter settings to production services

### Performance Optimization
1. **Appropriate Order**: Choose execution order based on plugin function
2. **Timeout Settings**: Set realistic timeouts for operations
3. **Log Levels**: Use INFO or WARN for production
4. **Resource Management**: Clean up resources properly

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test with various plugin configurations
5. Update documentation
6. Submit a pull request

## Support

- **BunkerWeb Documentation**: [docs.bunkerweb.io](https://docs.bunkerweb.io/)
- **Plugin Development**: [Plugin Documentation](https://docs.bunkerweb.io/latest/plugins/)
- **Community**: [Discord Server](https://bunkerity.discord.com/)

## License

This script is provided as-is for BunkerWeb plugin development. Check individual plugin licenses as generated.

---

**Happy Plugin Development!** 🚀