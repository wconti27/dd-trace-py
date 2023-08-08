#!/bin/bash

# Set the necessary variables
SOURCE_FOLDER_PATH="./documentation/generated"
DEST_FOLDER_PATH="APM-Integration-Docs/documentation/generated/python"
GITHUB_ACCESS_TOKEN="your-github-access-token"

mkdir -p "temp"
cd "temp"

git clone https://$INTEGRATION_DOCS_ACCESS_TOKEN@github.com/DataDog/APM-Integration-Docs.git

mkdir -p "$DEST_FOLDER_PATH"

cd ".."

ls -a

# Copy the files from the source directory to the destination directory
cp -r "$SOURCE_FOLDER_PATH"/* "./temp/$DEST_FOLDER_PATH"

cd "temp/APM-Integration-docs"

# Commit and push the changes to the destination repository
git add "$DEST_FOLDER_PATH"
git commit -m "Update Python documentation files"
git push "https://$INTEGRATION_DOCS_ACCESS_TOKEN@github.com/DataDog/APM-Integration-Docs.git" docs