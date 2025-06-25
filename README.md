# GitHub Dependabot reporter

This project contains scripts for querying GitHub Dependabot alert advisories, generating a CSV report
and uploading this to blob storage.

## Installation

Dependencies for this project are managed using [uv](https://docs.astral.sh/uv/).
With uv installed, change into the project directory and run:

    uv sync

Activate the virtualenv like so:

    source .venv/bin/activate

To run Python commands in the activated virtualenv, thereafter run them like so:

    python manage.py

Manage new or updated project dependencies with uv also, like so:

    uv add newpackage==1.0

## Environment variables

This project uses **python-dotenv** to set environment variables (in a `.env` file).
The following variables are required for the project to run:

    GITHUB_TOKEN
    GITHUB_ORGANISATION
    SEVERITY_MIN_DESC
    AZURE_STORAGE_CONNECTION_STRING
