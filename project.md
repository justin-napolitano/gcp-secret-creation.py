---
slug: github-gcp-secret-creation-py
id: github-gcp-secret-creation-py
title: Manage GCP Secrets with Python Script Automation
repo: justin-napolitano/gcp-secret-creation.py
githubUrl: https://github.com/justin-napolitano/gcp-secret-creation.py
generatedAt: '2025-11-24T21:34:52.250Z'
source: github-auto
summary: >-
  A Python script for creating, overwriting, and deleting secrets in Google Cloud Platform's Secret
  Manager using YAML and environment variables.
tags:
  - google-cloud-secret-manager
  - python
  - yaml
  - dotenv
  - gcp
seoPrimaryKeyword: gcp secret management python
seoSecondaryKeywords:
  - google cloud secrets
  - python secret manager
  - yaml configuration
  - environment variables
  - gcp automation
seoOptimized: true
topicFamily: automation
topicFamilyConfidence: 0.9
kind: project
entryLayout: project
showInProjects: true
showInNotes: false
showInWriting: false
showInLogs: false
---

A Python script to manage secrets in Google Cloud Platform's Secret Manager. It supports creating, overwriting, and deleting secrets based on YAML configuration files and environment variables.

## Features

- Create new secrets in GCP Secret Manager
- Add secret versions with payloads from environment variables
- Overwrite existing secrets
- Delete secrets specified in configuration
- Configurable via YAML files and environment variables

## Tech Stack

- Python 3.6+
- Google Cloud Secret Manager API (`google-cloud-secret-manager`)
- Environment variable management (`python-dotenv`)
- YAML parsing (`pyyaml`)

## Getting Started

### Prerequisites

- Python 3.6 or higher
- Google Cloud SDK installed and authenticated
- Service account JSON key with Secret Manager permissions

### Installation

```bash
# Clone the repository
git clone https://github.com/justin-napolitano/gcp-secret-creation.py.git
cd gcp-secret-creation.py

# Create and activate a virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install google-cloud-secret-manager python-dotenv pyyaml
```

### Setup

1. Create a `.env` file in the root directory with your project and secret values:

```env
PROJECT_NAME=your_project_name
FAKE_MASTODON_USERNAME=fake_username
FAKE_MASTODON_PASSWORD=fake_password
```

2. Create a YAML file (e.g. `secrets.yaml`) listing the secrets to manage:

```yaml
secrets:
  - id: "FAKE_MASTODON_USERNAME"
    env_var: "FAKE_MASTODON_USERNAME"
  - id: "FAKE_MASTODON_PASSWORD"
    env_var: "FAKE_MASTODON_PASSWORD"
```

### Running the Script

```bash
python scrt-creation.py --secrets-file secrets.yaml
```

#### Available Arguments

- `--url`: Base URL for API endpoint (default: `http://localhost:8080`)
- `--test`: Delete secrets after testing
- `--overwrite`: Overwrite existing secrets
- `--delete`: Delete secrets specified in the YAML file
- `--secrets-file`: Path to the YAML secrets configuration file (default: `secrets.yaml`)

## Project Structure

- `scrt-creation.py`: Main script managing secret creation, versioning, and deletion
- `conf.example.yaml`: Example YAML configuration for secrets
- `mastodon-secrets.yaml`: Sample secrets configuration for Mastodon credentials
- `env.example`: Example environment variables file
- `secret.json`: GCP service account credentials (should be secured and not committed)
- `readme.md`: Project documentation

## Future Work / Roadmap

- Add automated testing for secret management operations
- Support for secret rotation scheduling
- Enhanced error handling and logging
- Integration with CI/CD pipelines
- Support for multiple GCP projects or environments
- Add support for other secret backends

---

*Note: The repository currently lacks a detailed description and some documentation sections. The above assumes typical usage patterns based on the provided files and code snippets.*

