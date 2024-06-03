import pyshark
import requests
import base64
from datetime import datetime, timedelta
from flask import Flask, jsonify, request, render_template
from threading import Thread
from langchain.chains.combine_documents import create_stuff_documents_chain
from langchain.chains import create_retrieval_chain
from langchain.chains import create_history_aware_retriever
from langchain_core.messages import HumanMessage, AIMessage
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.prompts import MessagesPlaceholder
from langchain_community.llms import Ollama
from langchain_community.embeddings import OllamaEmbeddings
from langchain_community.vectorstores import FAISS

app = Flask(__name__)
recent_reports = []

tshark_path = 'C:/Program Files/Wireshark/tshark.exe'
capture = pyshark.LiveCapture(interface='Wi-Fi', tshark_path=tshark_path, bpf_filter='tcp port 80 or tcp port 443')

API_KEY = '2e720b0e9f107672e60359d96024aee9dac3e02fbbe7c607e9e7ff144cb9438f'
headers = {
    'x-apikey': API_KEY
}
processed_urls = set()

# Optimized Ollama setup
llm = Ollama(model='LLM_M11209207_model')
embeddings = OllamaEmbeddings()
vector = FAISS.from_texts(['This class is Applying Large Language Models in Cybersecurity Systems.'], embeddings)
retriever = vector.as_retriever()

# Optimized Prompt Template for Document Chain
prompt_document = ChatPromptTemplate.from_messages([
    ('system', 'You are an expert in cybersecurity. Based on the following security report, provide a comprehensive, professional, and detailed response addressing the user\'s question. Use specific data from the report to support your response, and ensure the response is well-organized and split into paragraphs for clarity. Separate each paragraph with a blank line. Each response should begin with "KL AI:":\n\n{context}'),
    ('user', '{input}'),
])
document_chain = create_stuff_documents_chain(llm, prompt_document)

# Optimized Prompt Template for History Aware Retriever
prompt_history = ChatPromptTemplate.from_messages([
    MessagesPlaceholder(variable_name="chat_history"),
    ("user", "{input}"),
    ("system", 'You are an expert in cybersecurity. Based on the following security report and the previous conversation, provide a comprehensive, professional, and detailed response addressing the user\'s question. Use specific data from the report to support your response, and ensure the response is well-organized and split into paragraphs for clarity. Separate each paragraph with a blank line. Each response should begin with "KL AI:":\n\n{context}'),
])
retriever_chain = create_history_aware_retriever(llm, retriever, prompt_history)
retrieval_chain = create_retrieval_chain(retriever_chain, document_chain)

chat_history = []

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

        response = requests.get(vt_url, headers=headers, timeout=10)
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
            domain_response = requests.get(domain_url, headers=headers, timeout=10) 

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
            print(f"Generated report for {url}: {report}")
            return report
        else:
            print(f"Error {response.status_code}: {response.text}") 
            return f"Error {response.status_code}: {response.text}"
    except Exception as e:
        print(f"Failed to get report for {url}: {str(e)}")
        return f"Failed to get report for {url}: {str(e)}"

def save_report(report):
    global recent_reports
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    recent_reports.append({'timestamp': timestamp, 'report': report, 'url': report.get('URL', 'N/A')})
    cutoff_time = datetime.now() - timedelta(minutes=10)
    recent_reports = [r for r in recent_reports if datetime.strptime(r['timestamp'], '%Y-%m-%d %H:%M:%S') > cutoff_time]
    print(f"Saved report: {recent_reports[-1]}")  

def packet_capture():
    for packet in capture.sniff_continuously():
        try:
            url = extract_url_from_packet(packet)
            if url and url not in processed_urls:
                processed_urls.add(url)
                response = requests.post('http://localhost:5000/classify', json={'url': url}, timeout=10)
                classification = response.json().get('classification')
                print(f'URL: {url} - Classification: {classification}')
                if classification == 1:
                    report = get_virustotal_report(url)
                    save_report(report)
        except Exception as e:
            print(f'Error processing packet: {e}')

@app.route('/classify', methods=['POST'])
def classify():
    data = request.json
    url = data.get('url')

    response = requests.post('http://localhost:5000/classify', json={'url': url}, timeout=10)
    classification = response.json().get('classification')
    return jsonify({'classification': classification})

@app.route('/get_reports', methods=['GET'])
def get_reports():
    return jsonify(recent_reports)

@app.route('/get_reports_in_time_range', methods=['POST'])
def get_reports_in_time_range():
    data = request.json
    start_time = datetime.strptime(data.get('start_time'), '%Y-%m-%d %H:%M:%S')
    end_time = datetime.strptime(data.get('end_time'), '%Y-%m-%d %H:%M:%S')

    filtered_reports = [
        report for report in recent_reports 
        if start_time <= datetime.strptime(report['timestamp'], '%Y-%m-%d %H:%M:%S') <= end_time
    ]

    return jsonify(filtered_reports)

@app.route('/chat', methods=['POST'])
def chat():
    global chat_history
    user_input = request.json.get('message')
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    if recent_reports:
        context = recent_reports[-1]['report']
    else:
        context = "No recent reports available."

    response = retrieval_chain.invoke({
        'input': user_input,
        'chat_history': chat_history,
        'context': context, 
    })

    response_text = response['answer'].strip()

    # Ensure 'KL AI:' only appears once at the start
    response_text = f'KL AI: {response_text}'

    chat_history.append({'role': 'user', 'content': user_input, 'timestamp': timestamp})
    chat_history.append({'role': 'ai', 'content': response_text, 'timestamp': timestamp})

    cutoff_time = datetime.now() - timedelta(minutes=10)
    chat_history = [msg for msg in chat_history if datetime.strptime(msg['timestamp'], '%Y-%m-%d %H:%M:%S') > cutoff_time]

    return jsonify({'response': response_text})


@app.route('/')
def index():
    return render_template('SystemInterface.html')


if __name__ == '__main__':
    capture_thread = Thread(target=packet_capture)
    capture_thread.start()
    app.run(port=5001, debug=True)
