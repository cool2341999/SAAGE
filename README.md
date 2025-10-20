# SAAGE: Synergistic Autonomous Agent for Generating Cybersecurity Event Evaluations
An automated routing security incident analysis pipeline—an MCP-driven framework that leverages Large Language Models (LLMs) for multi-source data comprehension, correlation, visualization, and report generation.

This work demonstrates the potential of LLM-driven, agent-based pipelines to scale cybersecurity operations—enhancing response timeliness, reproducibility, and analyst productivity.

## Agent Design Framework
The architecture is designed to perform comprehensive and automated analysis of cybersecurity incidents. It covers the entire workflow from anomaly detection, multi-source data and intelligence collection, data correlation and visualization, contextual event intelligence association, to automated report generation and formatting.

By leveraging the capabilities of LLMs and MCP (Model Context Protocol), the system can dynamically switch between different LLM providers at various nodes based on requirements. The overall architecture is illustrated below:

<img width="80%" height="auto" alt="Architecture Diagram" src="https://github.com/user-attachments/assets/ba4a1c38-6f94-49ce-b3c4-fabc6d0ef422" />

## Features
The agent implements the following core capabilities:

* Monitoring & Alerting - Continuous surveillance and notification of security events

* Correlation & Analysis - Multi-source data integration and analytical processing

* Motivation & Intent Analysis - Assessment of threat actor objectives and strategies

* Tracking & Evaluation - Ongoing monitoring and assessment of security incidents

* Reporting & Warning - Automated generation of comprehensive reports and alerts

## Agent Implementation Procedure
The current workflow design, shown below, enables fully automated analysis of routing security incidents. It comprehensively leverages search engines, internal and external traffic data, and BGP RIB data to analyze specific network events.

This implementation allows for flexible LLM substitution and can be extended with new MCP capabilities.

<img width="80%" height="auto" alt="Workflow Diagram" src="https://github.com/user-attachments/assets/0a8f63c8-11fb-4821-8ebd-0259eb1ec37d" />

A sample excerpt from an analysis report is shown below:

<img width="80*" height="auto" alt="Sample Report" src="https://github.com/user-attachments/assets/56ba0ca4-8a0d-44e7-bef0-72126a0f8213" />

## Usage
* Install Dify - Follow the installation guide at: https://docs.dify.ai/en/introduction

* Import Workflow - Import the workflow configuration YAML file into Dify

* Configure MCP Services - Set up and enable required MCP services in Dify configuration. Some services may require prior authorization (e.g., Google Search, Cloudflare Radar)

* Configure LLM Models - Modify and configure your preferred LLM models (e.g., Gemini, GPT, DeepSeek)

* Deploy and Run - Publish the Dify application, start the program, input the analysis target and date range, and await the generation of the comprehensive report


