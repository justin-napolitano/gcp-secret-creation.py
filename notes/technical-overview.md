---
slug: github-gcp-secret-creation-py-note-technical-overview
id: github-gcp-secret-creation-py-note-technical-overview
title: GCP Secret Manager Script
repo: justin-napolitano/gcp-secret-creation.py
githubUrl: https://github.com/justin-napolitano/gcp-secret-creation.py
generatedAt: '2025-11-24T18:36:51.490Z'
source: github-auto
summary: >-
  This repo contains a Python script to manage secrets in Google Cloud
  Platform's Secret Manager. It lets you create, overwrite, and delete secrets
  based on YAML configs and environment variables.
tags: []
seoPrimaryKeyword: ''
seoSecondaryKeywords: []
seoOptimized: false
topicFamily: null
topicFamilyConfidence: null
kind: note
entryLayout: note
showInProjects: false
showInNotes: true
showInWriting: false
showInLogs: false
---

This repo contains a Python script to manage secrets in Google Cloud Platform's Secret Manager. It lets you create, overwrite, and delete secrets based on YAML configs and environment variables.

## Key Features

- Create and add secret versions
- Overwrite or delete existing secrets
- Configurable using YAML and environment variables

## Tech Stack

- Python 3.6+
- Google Cloud Secret Manager API
- Environment variables with `python-dotenv`
- YAML handling using `pyyaml`

## Quick Start

1. Clone the repo:
   ```bash
   git clone https://github.com/justin-napolitano/gcp-secret-creation.py.git
   cd gcp-secret-creation.py
   ```

2. Set up your environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # For Windows, use: venv\Scripts\activate
   pip install -r requirements.txt
   ```

3. Configure `.env` and create your `secrets.yaml`.

4. Run the script:
   ```bash
   python scrt-creation.py --secrets-file secrets.yaml
   ```

### Gotchas

- Ensure your GCP service account has Secret Manager permissions.
- Do not commit your `secret.json` credentials.
