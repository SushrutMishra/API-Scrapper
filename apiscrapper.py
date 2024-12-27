import os
import re
import time
import requests
from bs4 import BeautifulSoup

# Configure sensitive patterns
SENSITIVE_PATTERNS = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "API Key": r"(?i)apikey\s*[:=]\s*[a-zA-Z0-9\-]{20,}",
    "Password": r"(?i)password\s*[:=]\s*.+",
}

# Search repositories on GitHub
def search_github_repos(username):
    repos = []
    page = 1
    while True:
        url = f"https://github.com/{username}?page={page}&tab=repositories"
        response = requests.get(url)
        if response.status_code != 200:
            print(f"Failed to fetch repositories for {username}. Status Code: {response.status_code}")
            break

        soup = BeautifulSoup(response.text, "html.parser")
        repo_links = soup.find_all("a", itemprop="name codeRepository")
        if not repo_links:
            break

        for link in repo_links:
            repo_name = link.text.strip()
            repos.append(f"https://github.com/{username}/{repo_name}")
        page += 1
        time.sleep(1)  # Rate limiting

    return repos

# Download and scan files for sensitive patterns
def scan_repo_branch(repo_url, branch):
    findings = {}
    try:
        branch_url = f"{repo_url}/archive/refs/heads/{branch}.zip"
        response = requests.get(branch_url)
        if response.status_code == 200:
            with open("repo.zip", "wb") as f:
                f.write(response.content)
            os.system("unzip -o repo.zip -d repo")
            traverse_and_scan("repo", findings)
#           os.system("rm -rf repo repo.zip")  # Cleanup
        else:
            print(f"Failed to download branch {branch} from {repo_url}. Status Code: {response.status_code}")
    except Exception as e:
        print(f"Error scanning branch {branch} in {repo_url}: {e}")
    return findings

# Traverse directories up to 6 levels deep
def traverse_and_scan(base_dir, findings, level=0, max_depth=6):
    if level > max_depth:
        return

    for root, _, files in os.walk(base_dir):
        depth = root[len(base_dir):].count(os.sep)
        if depth > max_depth:
            continue
        for file in files:
            file_path = os.path.join(root, file)
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                file_findings = scan_file_content(file_path, content)
                if file_findings:
                    findings[file_path] = file_findings

# Scan file content for sensitive patterns
def scan_file_content(file_path, content):
    findings = []
    for label, pattern in SENSITIVE_PATTERNS.items():
        matches = re.findall(pattern, content)
        if matches:
            findings.append((label, matches))
    return findings

# Get all branches for a repository
def get_repo_branches(repo_url):
    branches = []
    url = f"{repo_url}/branches/all"
    response = requests.get(url)
    if response.status_code == 200:
        soup = BeautifulSoup(response.text, "html.parser")
        branch_links = soup.find_all("a", class_="branch-name")
        branches = [link.text.strip() for link in branch_links]
    else:
        print(f"Failed to fetch branches for {repo_url}. Status Code: {response.status_code}")
    return branches

# Generate a report
def generate_report(username, repo_url, branch, findings, output_file):
    with open(output_file, "a") as f:
        f.write(f"\nReport for {username}/{repo_url} (Branch: {branch})\n")
        for file_path, issues in findings.items():
            f.write(f"\nFile: {file_path}\n")
            for label, matches in issues:
                f.write(f"  - {label}: {', '.join(matches)}\n")

# Main function
def main():
    input_file = input("Enter the path to the file with GitHub usernames: ")
    output_file = input("Enter the path for the output report file: ")

    try:
        with open(input_file, "r") as file:
            usernames = [line.strip() for line in file if line.strip()]

        for username in usernames:
            print(f"\nSearching repositories for user: {username}")
            repos = search_github_repos(username)
            for repo_url in repos:
                print(f"Scanning repository: {repo_url}")
                branches = get_repo_branches(repo_url)
                for branch in branches:
                    print(f"  Scanning branch: {branch}")
                    findings = scan_repo_branch(repo_url, branch)
                    if findings:
                        generate_report(username, repo_url, branch, findings, output_file)
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()

