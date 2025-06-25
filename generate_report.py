import argparse
import csv
import logging
import os
import sys
from tempfile import NamedTemporaryFile
from time import sleep

from azure.storage.blob import BlobClient
from dotenv import load_dotenv
from github import Auth, Github, GithubException

# Load environment variables.
load_dotenv()
# Configure logging.
LOGGER = logging.getLogger()
LOGGER.setLevel(logging.INFO)
formatter = logging.Formatter("{asctime} | {levelname} | {message}", style="{")
handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.INFO)
handler.setFormatter(formatter)
LOGGER.addHandler(handler)
azure_logger = logging.getLogger("azure")
azure_logger.setLevel(logging.WARNING)


def get_repos(organisation, ignore_archived=True):
    """Function to query GitHub REST API for Dependabot alerts on non-archived repositories
    having a minimum severity value.
    """
    # Obtain a list of repositories.
    LOGGER.info(f"Querying GitHub organisation {organisation} for repositories")
    if ignore_archived:
        LOGGER.info("Ignoring archived repositories")

    repos_list = []
    for repo in organisation.get_repos():
        if ignore_archived and repo.archived:  # Ignore archived repos.
            continue
        repos_list.append(repo)

    LOGGER.info(f"Got {len(repos_list)} repositories")

    return repos_list


def generate_report(repos_list, csv_out, severity_min_desc="high"):
    severity_map = {
        "low": 0,
        "medium": 1,
        "high": 2,
        "critical": 3,
    }
    severity_min_value = severity_map[severity_min_desc]

    # Set up a CSV to generate the report.
    headers = [
        "repository_name",
        "repository_url",
        "created_at",
        "advisory__cve_id",
        "advisory__severity",
        "advisory__summary",
        "vulnerability__package__ecosystem",
        "vulnerability__package__name",
        "vulnerability__vulnerable_version_range",
        "dependency__manifest_path",
    ]
    writer = csv.writer(csv_out, quoting=csv.QUOTE_ALL)
    writer.writerow(headers)

    for repo in repos_list:
        LOGGER.info(f"Getting open Dependabot alerts for repository {repo.name}")
        dependabot_alerts = repo.get_dependabot_alerts(state="open")
        alerts_list = []

        try:
            for alert in dependabot_alerts:
                if severity_map[alert.security_advisory.severity] >= severity_min_value:
                    alerts_list.append(alert)
        except GithubException as e:  # Catch 'Dependabot alerts are disabled...' errors.
            LOGGER.info(e.message)
            sleep(1)  # Be a good citizen and pause between requests.
            continue

        LOGGER.info(f"Got {len(alerts_list)} alerts for {repo.name} having severity {severity_min_desc} or greater")

        for alert in alerts_list:
            writer.writerow(
                [
                    repo.name,
                    repo.html_url,
                    alert.created_at.strftime("%d/%b/%Y %H:%M:%S"),
                    alert.security_advisory.cve_id,
                    alert.security_advisory.severity,
                    alert.security_advisory.summary,
                    alert.security_vulnerability.package.ecosystem,
                    alert.security_vulnerability.package.name,
                    alert.security_vulnerability.vulnerable_version_range,
                    alert.dependency.manifest_path,
                ]
            )

        sleep(1)  # Be a good citizen and pause between requests.

    csv_out.flush()
    return True


def upload_file(source_path, container_name, conn_str, overwrite=True, enable_logging=True, blob_name=None):
    """Upload a single file at `source_path` to Azure blob storage (`blob_name` destination name is optional)."""
    if not blob_name:
        blob_name = os.path.basename(source_path)

    blob_client = BlobClient.from_connection_string(conn_str, container_name, blob_name)

    if enable_logging:
        LOGGER.info(f"Uploading {source_path} to container {container_name}/{blob_name}")

    with open(file=source_path, mode="rb") as data:
        blob_client.upload_blob(data, overwrite=overwrite, validate_content=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="""A script to query GitHub Dependabot alerts for the nominated organisation, and output a CSV report
        of security advisories having the nominated severity (or higher).""",
    )
    parser.add_argument(
        "-f",
        "--filename",
        help="CSV report output filename (default: github_dependabot_alerts.csv)",
        default="github_dependabot_alerts.csv",
        action="store",
        required=False,
    )
    parser.add_argument(
        "-s",
        "--severity",
        help="Severity minimum (low|medium|high|critical), default: high",
        default="high",
        action="store",
        required=False,
    )
    parser.add_argument(
        "-c",
        "--container",
        help="The destination container name (optional, default 'analytics')",
        default="analytics",
        action="store",
        required=False,
    )
    parser.add_argument(
        "--ignore_archived",
        help="Ignore archived repositories (optional), default: True",
        action="store_true",
        default=True,
        required=False,
    )
    args = parser.parse_args()

    github_token = os.getenv("GITHUB_TOKEN")
    auth = Auth.Token(github_token)
    github = Github(auth=auth)
    github_organisation = os.getenv("GITHUB_ORGANISATION")
    organisation = github.get_organization(github_organisation)
    repos_list = get_repos(organisation=organisation, ignore_archived=args.ignore_archived)
    severity_min_desc = args.severity

    # Write the Dependabot alerts report to a temporary file.
    csv_out = NamedTemporaryFile(mode="w", suffix=".csv")
    generate_report(repos_list, csv_out, severity_min_desc)
    # Upload the CSV to blob storage.
    conn_str = os.getenv("AZURE_STORAGE_CONNECTION_STRING")
    upload_file(csv_out.name, args.container, conn_str, blob_name=args.filename)
    csv_out.close()
