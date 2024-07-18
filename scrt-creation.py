# Import the necessary libraries
from google.cloud import secretmanager
import os
from dotenv import load_dotenv
import argparse
import yaml

def load_env():
    """Load environment variables from .env file."""
    load_dotenv()

def get_project_id():
    """Get the GCP project ID from environment variables."""
    return os.getenv("PROJECT_NAME")

def load_secrets_from_yaml(file_path):
    """Load secrets configuration from a YAML file."""
    with open(file_path, 'r') as file:
        secrets_config = yaml.safe_load(file)
    return secrets_config

def create_secret(client, parent, secret_id):
    """
    Create a new secret in Secret Manager.

    Args:
    - client: The Secret Manager client.
    - parent: The parent resource name.
    - secret_id: The ID of the secret to create.

    Returns:
    - The created secret.
    """
    try:
        secret = client.create_secret(
            request={
                "parent": parent,
                "secret_id": secret_id,
                "secret": {"replication": {"automatic": {}}},
            }
        )
        print(f"Created secret: {secret_id}")
        return secret
    except Exception as e:
        print(f"Error creating secret {secret_id}: {e}")
        return None

def add_secret_version(client, secret_name, payload):
    """
    Add a new version to the secret with the given payload.

    Args:
    - client: The Secret Manager client.
    - secret_name: The name of the secret.
    - payload: The secret payload to add.

    Returns:
    - The added secret version.
    """
    try:
        encoded_payload = payload.encode('utf-8')
        version = client.add_secret_version(
            request={"parent": secret_name, "payload": {"data": encoded_payload}}
        )
        print(f"Added secret version to: {secret_name}")
        return version
    except Exception as e:
        print(f"Error adding secret version to {secret_name}: {e}")
        return None

def access_secret_version(client, version_name):
    """
    Access the secret version and return the payload.

    Args:
    - client: The Secret Manager client.
    - version_name: The name of the secret version.

    Returns:
    - The secret payload.
    """
    try:
        response = client.access_secret_version(request={"name": version_name})
        payload = response.payload.data.decode("UTF-8")
        print(f"Accessed secret version: {version_name}")
        return payload
    except Exception as e:
        print(f"Error accessing secret version {version_name}: {e}")
        return None

def delete_secret(client, secret_name):
    """
    Delete the secret from Secret Manager.

    Args:
    - client: The Secret Manager client.
    - secret_name: The name of the secret to delete.

    Returns:
    - None
    """
    try:
        client.delete_secret(request={"name": secret_name})
        print(f"Deleted secret: {secret_name}")
    except Exception as e:
        print(f"Error deleting secret {secret_name}: {e}")

def secret_exists(client, secret_name):
    """
    Check if a secret exists.

    Args:
    - client: The Secret Manager client.
    - secret_name: The name of the secret to check.

    Returns:
    - bool: True if the secret exists, False otherwise.
    """
    try:
        client.get_secret(request={"name": secret_name})
        return True
    except Exception as e:
        return False

def main():
    load_env()
    parser = argparse.ArgumentParser(description='Handle secrets in GCP Secret Manager.')
    parser.add_argument('--url', type=str, default="http://localhost:8080", help='Base URL for the API endpoint')
    parser.add_argument('--test', action='store_true', help='Flag to delete secrets after testing')
    parser.add_argument('--overwrite', action='store_true', help='Flag to overwrite existing secrets')
    parser.add_argument('--delete', action='store_true', help='Flag to delete secrets specified in the YAML file')
    parser.add_argument('--secrets-file', type=str, default='secrets.yaml', help='Path to the YAML file with secrets configuration')
    args = parser.parse_args()

    project_id = get_project_id()
    if not project_id:
        print("Error: PROJECT_NAME environment variable not set.")
        return

    secrets_config = load_secrets_from_yaml(args.secrets_file)
    if not secrets_config or 'secrets' not in secrets_config:
        print("Error: Invalid secrets configuration.")
        return

    client = secretmanager.SecretManagerServiceClient()
    parent = f"projects/{project_id}"

    for secret_config in secrets_config['secrets']:
        secret_id = secret_config['id']
        env_var = secret_config['env_var']
        secret_value = os.getenv(env_var)

        secret_name = f"{parent}/secrets/{secret_id}"

        # Delete the secret if --delete flag is set
        if args.delete:
            if secret_exists(client, secret_name):
                delete_secret(client, secret_name)
            continue

        if not secret_value:
            print(f"Error: Environment variable {env_var} not set.")
            continue

        # Check and optionally delete existing secrets
        if secret_exists(client, secret_name) and args.overwrite:
            delete_secret(client, secret_name)

        # Create and add version for the secret
        secret = create_secret(client, parent, secret_id)
        if secret:
            add_secret_version(client, secret.name, secret_value)

        # Access and print the latest version of the secret (example)
        if secret:
            version_name = f"{secret.name}/versions/latest"
            payload = access_secret_version(client, version_name)
            if payload:
                print(f"Plaintext for {secret_id}: {payload}")

        # Delete the secret to clean up if --test flag is set
        if args.test and secret:
            delete_secret(client, secret.name)

if __name__ == "__main__":
    main()
