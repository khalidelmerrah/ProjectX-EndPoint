# ProjectX Desktop: 
## Advanced Endpoint Security Dashboard

ProjectX Desktop is a comprehensive, local-first endpoint security auditing tool designed to provide real-time visibility into your system's security posture. Built with **Python (PyQt6)** and powered by **OSQuery**, it offers enterprise-grade telemetry without the need for a central server.

![ProjectX Dashboard](https://i.ibb.co/Y4TkxPT3/Project-X-Security-Preview-1.webp)

## 🛡️ Key Features

-   **Real-time Asset Inventory**: Automatically detects installed software, versions, and installation dates.
-   **Vulnerability Scanning**: Matches installed software against the NIST NVD (National Vulnerability Database) to identify known CVEs.
-   **Network Monitoring**: Visualizes active TCP/UDP connections and listening ports (Exposure Monitor).
-   **Threat Intelligence**: Fetches and displays the latest security advisories from WatchGuard and other sources.
-   **System Health**: Monitors battery status, security center settings (AV/Firewall), and system crashes.
-   **Granular Control**: On-demand scanning for specific modules (Software, Network, Drivers, etc.).
-   **Secure Architecture**: API keys are encrypted using the system `keyring` (Windows Credential Manager).
-   **Privacy First**: All data is stored locally in a SQLite database (`projectx.db`). No telemetry is sent to the cloud.

## 🚀 Installation

### Prerequisites
-   **Windows 10/11** (x64)
-   **Python 3.10+**
-   **OSQuery**: The application requires `osqueryi.exe`. It looks for it in the system PATH or a local `bin/` directory.
    -   *Download*: [osquery.io](https://osquery.io/downloads/official/)

### Steps

1.  **Clone the Repository**
    ```bash
    git clone https://github.com/khalidelmerrah/projectx-desktop.git
    cd projectx-desktop
    ```

2.  **Install Dependencies**
    It is recommended to use a virtual environment.
    ```bash
    python -m venv .venv
    .\.venv\Scripts\activate
    pip install -r requirements.txt
    ```

3.  **Run the Application**
    ```bash
    python app.py
    ```

## ⚙️ Configuration

### API Keys
To enable full vulnerability matching and AI features, configure your API keys in the **Configuration > Settings** tab:
-   **NIST API Key**: Required for faster CVE lookups (High rate limit). [Get Key](https://nvd.nist.gov/developers/request-an-api-key)
-   **Gemini API Key**: Required for "AI Explain" features on risk analysis.

*Note: Keys are stored securely in your OS Keychain, not in plain text files.*

### Portable Deployment
To run ProjectX portably:
1.  Place `osqueryi.exe` in a `bin/` folder inside the project directory.
2.  The application will prioritize this binary over the system installation.

## 🛠️ Usage

-   **Dashboard**: View high-level KPIs and top risks.
-   **Assets**: Inspect Software, Drivers, Certificates, and Browser Extensions.
-   **Network**: active connections and hosts file analysis.
-   **System**: Check Battery health, Windows Updates, and Persistence items (Startup apps).
-   **Refeshing Data**: Use the "Refresh" button on any tab to update that specific dataset.

## 🧩 Architecture

-   **Frontend**: PyQt6 with a custom dark theme.
-   **Backend**: Python `workers` utilizing `QThread` for non-blocking UI.
-   **Data Source**: `osqueryi` (subprocess execution) + `psutil`.
-   **Database**: SQLite for local persistence (`db_manager.py`).

## 🐞 Troubleshooting

-   **Logs**: Check `projectx.log` for detailed error messages.
-   **Missing Data**: Ensure `osqueryi` is installed and accessible.
-   **Crash on Exit**: A known issue with logging cleanup has been resolved in the latest build.

## 📄 License

MIT License. See [LICENSE](./LICENSE) for details.
