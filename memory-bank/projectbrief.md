# Project Brief: Insect

## 1. Core Concept

Insect is a command-line security tool designed to scan locally cloned Git repositories for potential malicious code *before* any code execution occurs.

## 2. Primary Goal

To provide developers, security professionals, job candidates, and hobbyists with a reliable, user-friendly, pre-execution scanning tool that identifies malicious patterns, suspicious configurations, and other risk indicators within cloned codebases, thereby mitigating the risk of credential theft, malware execution, and other compromises originating from untrusted repositories.

## 3. Key Objectives

* **Threat Detection:** Accurately identify a range of malicious indicators using static code analysis, configuration file analysis, binary heuristics, and repository metadata analysis.
* **Actionable Warnings:** Present clear, understandable, and detailed reports (Console, JSON, HTML) highlighting potential risks, including severity levels, specific locations (file/line), and descriptions.
* **User Experience:** Offer a simple and intuitive command-line interface (`insect scan <path>`) with sensible defaults and clear configuration options.
* **Minimize False Positives:** Allow tuning (sensitivity levels, allowlists) to reduce noise and ensure user trust.
* **Extensibility:** Design with a modular architecture to facilitate future updates and addition of new analyzers.

## 4. Scope

### In Scope:

* Post-clone, pre-execution static analysis of local Git repositories.
* Analysis of source code (Python, JS, Shell, etc.), common configuration files (`Dockerfile`, `package.json`, `requirements.txt`, etc.), basic binary heuristics (entropy, YARA rules), and local Git metadata.
* Generation of reports in Console, JSON, and HTML formats.
* Command-line interface with configuration options (files and flags).
* Distribution as a PyPI package.

### Out of Scope (Initially):

* Real-time pre-clone analysis.
* Dynamic analysis / Sandboxing (running the code).
* Deep binary reverse engineering.
* General vulnerability scanning (SAST features not focused on *malicious intent* towards the user).
* Guaranteed detection of all threats.

## 5. Source of Truth

This document provides the high-level foundation. Detailed requirements, technical specifications, and implementation steps are elaborated in other Memory Bank files (`productContext.md`, `techContext.md`, `systemPatterns.md`) and the detailed Implementation Plan/Task List.
