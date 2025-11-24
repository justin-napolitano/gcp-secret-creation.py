---
slug: github-gcp-secret-creation-py-writing-overview
id: github-gcp-secret-creation-py-writing-overview
title: GCP Secret Management Made Easy with Python
repo: justin-napolitano/gcp-secret-creation.py
githubUrl: https://github.com/justin-napolitano/gcp-secret-creation.py
generatedAt: '2025-11-24T17:26:04.511Z'
source: github-auto
summary: >-
  Managing secrets can be a hassle, especially when you're juggling multiple
  environments and configurations. I created `gcp-secret-creation.py` to
  streamline this process for anyone using Google Cloud Platform’s Secret
  Manager. Let me walk you through it.
tags: []
seoPrimaryKeyword: ''
seoSecondaryKeywords: []
seoOptimized: false
topicFamily: null
topicFamilyConfidence: null
kind: writing
entryLayout: writing
showInProjects: false
showInNotes: false
showInWriting: true
showInLogs: false
---

Managing secrets can be a hassle, especially when you're juggling multiple environments and configurations. I created `gcp-secret-creation.py` to streamline this process for anyone using Google Cloud Platform’s Secret Manager. Let me walk you through it.

## What’s It All About?

At its core, this repository contains a Python script that interacts with Google Cloud Platform’s Secret Manager. The script allows you to create, update, and delete secrets easily using YAML configuration files and environment variables. Simple, right? 

I built this tool to handle the often cumbersome process of secret management. Secrets need to be carefully handled, and having a straightforward, reliable method to do so can save a lot of headaches.

## Key Features

Here’s what you can expect:

- **Create secrets**: Easily add new secrets to GCP.
- **Add versions**: Push new secret versions using values from your environment.
- **Overwrite existing secrets**: Update secrets when needed.
- **Delete secrets**: Remove any secrets defined in your YAML configuration.
- **Configurable**: Control everything through YAML files and environment variables.

## Tech Stack and Tools

I chose a lightweight and effective stack for this project:

- **Python 3.6+**: Lightweight and versatile, perfect for scripting.
- **Google Cloud Secret Manager API**: Handling secrets within GCP made simple.
- **python-dotenv**: Managing environment variables with ease.
- **pyyaml**: Excellent for parsing YAML files, which is essential for the configuration.

## Installation and Setup

Getting started is easy. Just follow these steps:

### Prerequisites

1. Python 3.6 or later installed on your machine.
2. Google Cloud SDK authenticated and set up.
3. A service account JSON key that has permissions for Secret Manager.

### Installation Steps

1. Clone the repository:
    ```bash
    git clone https://github.com/justin-napolitano/gcp-secret-creation.py.git
    cd gcp-secret-creation.py
    ```

2. Set up a virtual environment:
    ```bash
    python -m venv venv
    source venv/bin/activate  # Use venv\Scripts\activate on Windows
    ```

3. Install dependencies:
    ```bash
    pip install google-cloud-secret-manager python-dotenv pyyaml
    ```

### Configuration

You need to set up a couple of files to get things rolling:

1. Create a `.env` file to hold your project-specific values:
    ```env
    PROJECT_NAME=your_project_name
    FAKE_MASTODON_USERNAME=fake_username
    FAKE_MASTODON_PASSWORD=fake_password
    ```

2. Create a `secrets.yaml` file to specify what secrets need management:
    ```yaml
    secrets:
      - id: "FAKE_MASTODON_USERNAME"
        env_var: "FAKE_MASTODON_USERNAME"
      - id: "FAKE_MASTODON_PASSWORD"
        env_var: "FAKE_MASTODON_PASSWORD"
    ```

### Running the Script

Execute the Python script to manage your secrets:
```bash
python scrt-creation.py --secrets-file secrets.yaml
```

#### Options

The script comes equipped with command-line options:
- `--url`: Specify a base API URL (defaults to `http://localhost:8080`).
- `--test`: Deletes secrets after testing to keep things clean.
- `--overwrite`: Overwrites any existing secrets.
- `--delete`: Deletes secrets as listed in the YAML file.
- `--secrets-file`: Specify the path to your YAML file (defaults to `secrets.yaml`).

## Structural Overview

Here's a quick rundown of the project structure:
- **scrt-creation.py**: The main script for handling secrets.
- **conf.example.yaml**: A sample YAML configuration.
- **mastodon-secrets.yaml**: A template for managing Mastodon credentials.
- **env.example**: Sample environment variable setup.
- **secret.json**: Your GCP service account credentials (keep this safe!).
- **readme.md**: Documentation for the project.

## Design Decisions and Tradeoffs

I decided to go with YAML for configuration because it’s human-readable and easy to modify. Environment variables are great for security, keeping sensitive information out of your codebase. 

But let's be honest: this approach has its tradeoffs. YAML can be finicky and prone to errors if you're not careful with formatting. I believe the benefits outweigh the downsides in most scenarios, especially for teams that are already used to managing configurations this way.

## What’s Next?

Now that you know what this repo does, let's talk about future plans:

- **Automated testing**: I need to implement tests for secret management to ensure reliability.
- **Secret rotation scheduling**: Automating the rotation of secrets would be a great addition.
- **Enhanced error handling and logging**: Better feedback will smooth out the experience.
- **CI/CD integration**: Making it more DevOps-friendly.
- **Multiple GCP projects support**: I want it to scale seamlessly.
- **Diverse backend support**: Other secret management backends could be on the radar.

## Stay Updated

If you're interested in what I’m up to next or want to join the conversation, I share updates and insights on Mastodon, Bluesky, and Twitter/X. I love connecting with other developers and would be happy to hear your thoughts or suggestions!

In conclusion, `gcp-secret-creation.py` is a handy, straightforward tool for managing secrets in GCP. Give it a spin and let me know what you think!
