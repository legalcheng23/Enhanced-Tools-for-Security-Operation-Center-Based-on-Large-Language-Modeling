import pyshark
import requests
import vt
import base64
from datetime import datetime


tshark_path = 'C:/Program Files/Wireshark/tshark.exe'
capture = pyshark.LiveCapture(interface='Wi-Fi', tshark_path=tshark_path, bpf_filter='tcp port 80 or tcp port 443')


API_KEY = '2e720b0e9f107672e60359d96024aee9dac3e02fbbe7c607e9e7ff144cb9438f'

headers = {
    'x-apikey': API_KEY
}

processed_urls = set()

def extract_url_from_packet(packet):
    if 'HTTP' in packet:
        http_layer = packet['HTTP']
        if hasattr(http_layer, 'host') and hasattr(http_layer, 'request_uri'):
            return f"http://{http_layer.host}{http_layer.request_uri}"
    elif 'TLS' in packet and 'http' in str(packet['TLS']):
        if hasattr(packet.tls, 'handshake_extensions_server_name'):
            return f"https://{packet.tls.handshake_extensions_server_name}"
    return None

def get_virustotal_report(url):
    try:
        encoded_url = base64.urlsafe_b64encode(url.encode()).decode().strip('=')
        vt_url = f'https://www.virustotal.com/api/v3/urls/{encoded_url}'

        response = requests.get(vt_url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            attributes = data['data']['attributes']
            
            categories = attributes.get('categories', 'N/A')
            last_analysis_stats = attributes.get('last_analysis_stats', 'N/A')
            last_analysis_results = attributes.get('last_analysis_results', 'N/A')
            url_info = attributes.get('url', 'N/A')
            final_url = attributes.get('last_final_url', 'N/A')
            http_response_length = attributes.get('last_http_response_content_length', 'N/A')
            http_response_code = attributes.get('last_http_response_code', 'N/A')
            serving_ip_address = 'N/A'
            last_http_response_content_sha256 = attributes.get('last_http_response_content_sha256', 'N/A')
            first_submission_date = attributes.get('first_submission_date', 'N/A')
            last_submission_date = attributes.get('last_submission_date', 'N/A')
            last_analysis_date = attributes.get('last_analysis_date', 'N/A')
            redirection_chain = attributes.get('redirection_chain', 'N/A')
            last_http_response_headers = attributes.get('last_http_response_headers', {})
            content_type = last_http_response_headers.get('Content-Type', 'N/A')
            referrer_policy = last_http_response_headers.get('Referrer-Policy', 'N/A')
            content_length = last_http_response_headers.get('Content-Length', 'N/A')
            response_date = last_http_response_headers.get('Date', 'N/A')
            alt_svc = last_http_response_headers.get('Alt-Svc', 'N/A')
            

            def convert_timestamp(timestamp):
                if isinstance(timestamp, int):
                    return datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
                return 'N/A'
            
            first_submission_date = convert_timestamp(first_submission_date)
            last_submission_date = convert_timestamp(last_submission_date)
            last_analysis_date = convert_timestamp(last_analysis_date)
            

            domain = url.split('/')[2]

            domain_url = f'https://www.virustotal.com/api/v3/domains/{domain}'
            domain_response = requests.get(domain_url, headers=headers)
            
            if domain_response.status_code == 200:
                domain_data = domain_response.json()
                dns_records = domain_data['data']['attributes'].get('last_dns_records', [])
                if dns_records:
                    serving_ip_address = dns_records[0].get('value', 'N/A')
                else:
                    serving_ip_address = 'No DNS records found'
            else:
                serving_ip_address = f"Failed to get domain info: {domain_response.status_code}"
            

            report = {
                "URL": url_info,
                "Final URL": final_url,
                "Times Submitted": attributes.get('times_submitted', 'N/A'),
                "Categories": categories,
                "First Submission Date": first_submission_date,
                "Last Submission Date": last_submission_date,
                "Last Analysis Date": last_analysis_date,
                "Last Analysis Stats": last_analysis_stats,
                "Last HTTP Response Code": http_response_code,
                "HTTP Response Length": http_response_length,
                "HTTP Response Headers": last_http_response_headers,
                "Serving IP Address": serving_ip_address,
                "Last HTTP Response Content SHA256": last_http_response_content_sha256,
                "Redirection Chain": redirection_chain,
                "Content-Type": content_type,
                "Referrer-Policy": referrer_policy,
                "Content-Length": content_length,
                "Date": response_date,
                "Alt-Svc": alt_svc
            }
            return report
        else:
            return f"Error {response.status_code}: {response.text}"
    except Exception as e:
        return f"Failed to get report for {url}: {str(e)}"

def send_report_to_user(report):
    user_response = input("Would you like to further understand its risks? (yes/no): ")
    if user_response.lower() == 'yes':
        print("Here is a detailed risk report:")
        if isinstance(report, dict):
            for key, value in report.items():
                if isinstance(value, dict):
                    print(f"{key}:")
                    for sub_key, sub_value in value.items():
                        print(f"  {sub_key}: {sub_value}")
                else:
                    print(f"{key}: {value}")
        else:
            print(report)

print("Starting packet capture. Monitoring for HTTP and HTTPS traffic...")

for packet in capture.sniff_continuously():
    try:
        url = extract_url_from_packet(packet)
        if url and url not in processed_urls:
            processed_urls.add(url)
            response = requests.post('http://localhost:5000/classify', json={'url': url})
            classification = response.json().get('classification')
            print(f'URL: {url} - Classification: {classification}')
            if classification == 1:
                report = get_virustotal_report(url)
                send_report_to_user(report)
    except Exception as e:
        print(f'Error processing packet: {e}')