

![image](https://github.com/ChathurangaBW/DeepScan/assets/4383991/6fffa85d-c8a7-4f04-9e61-70c589843504)

# Nmap Scanner with SecurityTrails Integration

This Python script integrates with the SecurityTrails API to retrieve DNS history records for a given domain and allows users to perform detailed Nmap scans on selected IP addresses from the results.

### Features:
- Queries SecurityTrails API to fetch DNS history for a specified domain.
- Displays detailed DNS history records including IP addresses, organizations, and first/last seen dates.
- Enables users to select an IP address for Nmap scanning based on the retrieved DNS records.
- Executes Nmap scans with verbose output directly to the terminal.
- Provides an overall progress bar using `alive-progress` to track the status of multiple Nmap scans concurrently.

### Requirements:
- Python 3.6 or higher
- Dependencies listed in `requirements.txt`

### Usage:
1. Clone the repository.
2. Install dependencies using `pip install -r requirements.txt`.
3. Run the script and follow the prompts to query DNS history and perform Nmap scans.

### Notes:
- Ensure you have a valid API key for SecurityTrails (`API_KEY` in the script).
- Customize the script further based on your specific needs and preferences.

Feel free to contribute and improve this script. If you encounter any issues or have suggestions, please open an issue or submit a pull request.
