# Product Context: Insect

## 1. Problem Solved

Developers and others frequently clone Git repositories from potentially untrusted sources (e.g., public repos, job application challenges, tutorials). Malicious actors exploit this by disguising malware (credential stealers, keyloggers, backdoors) within seemingly legitimate projects. Social engineering tactics (fake recruiters, promising features) further lower user defenses. Running code from these repos without prior checks poses a significant security risk. Insect aims to bridge this gap by providing an easy-to-use *pre-execution* scanner.

## 2. Target Users

* **Software Developers:** Cloning dependencies, exploring new projects, reviewing code.
* **System Administrators / DevOps:** Evaluating automation scripts or infrastructure code.
* **Security Researchers:** Analyzing potentially malicious code samples.
* **Job Candidates:** Handling coding challenges provided as Git repositories.
* **Students & Hobbyists:** Experimenting with code found online.

## 3. Desired User Workflow & Experience

1.  **Installation:** User installs Insect easily via pip (`pip install insect-scanner`).
2.  **Cloning:** User clones a target Git repository using standard `git clone` commands.
3.  **Scanning:** User navigates *outside* the cloned directory and runs `insect scan /path/to/cloned/repo`.
4.  **Analysis:** Insect performs static analysis locally without executing any code from the target repo.
5.  **Reporting:** Insect outputs a clear report (default: console) summarizing findings, severity levels, and locations. Detailed JSON/HTML reports are available via flags (`--output-format`, `--output-path`).
6.  **Decision:** User reviews the report to make an informed decision about whether to trust and execute code from the repository.

**Experience Goals:**

* **Clarity:** Reports should be easy to understand, even for less technical users, clearly indicating the severity and nature of potential risks.
* **Actionability:** Findings should point to specific files/lines and provide enough context for investigation.
* **Speed:** While thoroughness is key, the scan should be reasonably fast for typical repository sizes.
* **Trustworthiness:** Minimize false positives through tuning options to maintain user confidence.
* **Simplicity:** The core CLI usage should be straightforward with sensible defaults.

## 4. Why This Project Exists

To provide a readily accessible, open-source tool specifically designed to address the growing threat of malware distributed via Git repositories, empowering users to protect themselves *before* potentially harmful code is executed. It fills a niche between basic linters and complex enterprise security suites or sandboxing environments.
