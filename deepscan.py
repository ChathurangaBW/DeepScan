import sys
import click
import requests
from alive_progress import alive_bar
import subprocess
from multiprocessing import Pool, Manager

# Global variable for API key
API_KEY = "ohioBm5M5UXF41A-z8rnReF39GDhao4p"

# Function to query DNS history using SecurityTrails API
def query_dns_history(domain):
    url = f"https://api.securitytrails.com/v1/history/{domain}/dns/a"
    headers = {
        "APIKEY": API_KEY,
        "Accept": "application/json"
    }

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()  # Raise an exception for HTTP errors
        return response.json().get('records', [])
    except requests.exceptions.RequestException as e:
        print(f"Error querying DNS history: {e}")
        sys.exit(1)

# Function to perform Nmap scan on a single IP with verbose output
def perform_nmap_scan(ip, output_queue):
    output_file = f"{ip}_nmap_scan.txt"
    command = f"nmap -sV -A -O -T4 -p- --script=default,safe,version,vulners --max-retries 3 -oN {output_file} {ip}"

    # Capture and display output in real-time
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
    for line in iter(process.stdout.readline, ''):
        output_queue.put(line.strip())
    process.stdout.close()
    process.wait()

# Function to display progress bar for Nmap scans using alive-progress
def scan_with_progress(ip_addresses):
    with alive_bar(len(ip_addresses), title="Overall Progress") as bar:
        manager = Manager()
        output_queue = manager.Queue()

        # Start a process pool to perform Nmap scans
        with Pool(processes=len(ip_addresses)) as pool:
            results = [pool.apply_async(perform_nmap_scan, (ip, output_queue)) for ip in ip_addresses]

            # Monitor output queue for verbose display
            while any(not result.ready() for result in results):
                while not output_queue.empty():
                    line = output_queue.get()
                    click.echo(line)
                bar(len([result for result in results if result.ready()]))
                bar()

            for result in results:
                result.get()  # Ensure all processes complete

@click.command()
@click.option('--domain', prompt='Enter the domain name to query', help='Domain name to query DNS history')
def main(domain):
    # Query DNS history
    click.echo(f"Querying DNS history for domain: {domain} ...")
    records = query_dns_history(domain)

    if not records:
        click.echo(f"No records found for domain '{domain}'. Exiting.")
        sys.exit(1)

    # Display DNS history results with index
    click.echo("\nDNS History Results:")
    click.echo("{:<5} {:<15} {:<35} {:<12} {:<12}".format("Index", "IP Addresses", "Organization", "First Seen", "Last Seen"))
    click.echo("-" * 80)

    for index, record in enumerate(records):
        ip = record['values'][0]['ip']
        org = record['organizations'][0] if 'organizations' in record else ''
        first_seen = record['first_seen']
        last_seen = record['last_seen']
        click.echo("{:<5} {:<15} {:<35} {:<12} {:<12}".format(index, ip, org, first_seen, last_seen))

    # Prompt user to select an IP address for Nmap scan
    selected_ip = click.prompt("\nEnter the IP address to perform Nmap scan", type=str)

    # Validate selected IP against retrieved records
    if selected_ip not in [record['values'][0]['ip'] for record in records]:
        click.echo("Invalid IP address. Please select from the displayed list.")
        sys.exit(1)

    # Perform Nmap scan
    click.echo(f"\nPerforming Nmap scan on IP: {selected_ip} ...")
    scan_with_progress([selected_ip])
    click.echo(f"\nNmap scan complete. Results saved in: {selected_ip}_nmap_scan.txt")

if __name__ == "__main__":
    main()
