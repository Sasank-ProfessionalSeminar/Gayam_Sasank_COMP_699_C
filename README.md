# Configuration Drift Detector

## Project Overview

The Configuration Drift Detector is a Streamlit-based application designed by SecureSys Solutions to identify, assess, and remediate configuration drift across IT infrastructure.

Configuration drift refers to the unintentional or undocumented changes in server, device, or application configurations over time. These changes often go unnoticed and can cause serious problems including compliance failures, outages, and security breaches.

This system allows IT teams to compare configuration snapshots, score risks, visualize drift patterns, and plan remediations in a scalable, automated way.

## Key Features

- Upload and compare configuration files (baseline vs. current).
- Highlight and categorize differences (e.g., added users, changed ports).
- Automatically score risk based on the severity of changes.
- Visualize drift trends using heatmaps and graphs.
- Detect anomalies and recurring patterns across multiple systems.
- Generate remediation plans with estimated effort.
- Provide root-cause analysis hints for each detected drift.
- Historical tracking and gamification options.
- Secure user login with role-based access (Admin, Analyst, Manager).

## Technology Stack

- Frontend: Streamlit
- Backend: Python
- Visualization: Plotly or Matplotlib
- Storage: Local JSON or File-based for mock config data
- Security: Role-based access, encryption at rest and in transit

## How to Run

### Requirements

- Python 3.9 or higher
- Dependencies in `requirements.txt`

### Installation

```bash
git clone https://github.com/<your-username>/configuration-drift-detector.git
cd configuration-drift-detector
pip install -r requirements.txt
