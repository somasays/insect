# System Patterns: Insect

## 1. Overall Architecture

Insect is a **Modular Command-Line Application** built in Python. It follows a standard Python package structure suitable for PyPI distribution. Execution is triggered via a single entry point, which orchestrates various analysis and reporting components.

```mermaid
graph TD
    CLI[CLI Entry Point (`insect` command)] -->|args| ArgParser(Argument Parser);
    ArgParser -->|config path| ConfigHandler(Config Handler);
    ArgParser -->|repo path, flags| CoreOrchestrator(Core Orchestrator);
    ConfigHandler -->|merged config| CoreOrchestrator;

    subgraph CoreOrchestrator ["src/insect/core.py"]
        FileDiscovery(File Discovery);
        Dispatch(Analyzer Dispatcher);
        Aggregation(Results Aggregation);
        FileDiscovery --> Dispatch --> Aggregation;
    end

    Dispatch --> AnalyzerModules;
    subgraph AnalyzerModules ["src/insect/analysis/"]
        Static(Static Analyzer);
        Config(Config Analyzer);
        Binary(Binary Analyzer);
        Metadata(Metadata Analyzer);
    end

    Aggregation --> ReporterModules;
    subgraph ReporterModules ["src/insect/reporting/"]
        Console(Console Reporter);
        JSON(JSON Reporter);
        HTML(HTML Reporter);
    end

    CoreOrchestrator -->|scan results| ReporterModules;
    ReporterModules -->|formatted output| Output(Console/Files);
