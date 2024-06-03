import pandas as pd
import requests
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

dataset_path = 'C:/Users/legal/Downloads/phiusiil+phishing+url+dataset/PhiUSIIL_Phishing_URL_Dataset.csv'

try:
    df = pd.read_csv(dataset_path)
    print("Data loaded successfully")
except FileNotFoundError:
    print(f"File not found: {dataset_path}")
    df = None

if df is not None:
    df = df[['URL', 'label']].head(10000)

    def test_basic_system(url):
        response = requests.post('http://localhost:5000/classify', json={'url': url})
        classification = response.json().get('classification')
        return classification

    def test_combined_system_batch(urls):
        response = requests.post('http://localhost:5001/batch_classify', json={'urls': urls})
        classifications = response.json()
        return [result['classification'] for result in classifications]

    # Test BERT model system
    df['basic_classification'] = df['URL'].apply(test_basic_system)
    basic_accuracy = accuracy_score(df['label'], df['basic_classification'])
    basic_precision = precision_score(df['label'], df['basic_classification'])
    basic_recall = recall_score(df['label'], df['basic_classification'])
    basic_f1 = f1_score(df['label'], df['basic_classification'])

    print(f"Basic System - Accuracy: {basic_accuracy}")
    print(f"Basic System - Precision: {basic_precision}")
    print(f"Basic System - Recall: {basic_recall}")
    print(f"Basic System - F1 Score: {basic_f1}")

    # Test combined system with batch processing
    urls = df['URL'].tolist()
    df['combined_classification'] = test_combined_system_batch(urls)
    combined_accuracy = accuracy_score(df['label'], df['combined_classification'])
    combined_precision = precision_score(df['label'], df['combined_classification'])
    combined_recall = recall_score(df['label'], df['combined_classification'])
    combined_f1 = f1_score(df['label'], df['combined_classification'])

    print(f"Combined System - Accuracy: {combined_accuracy}")
    print(f"Combined System - Precision: {combined_precision}")
    print(f"Combined System - Recall: {combined_recall}")
    print(f"Combined System - F1 Score: {combined_f1}")
