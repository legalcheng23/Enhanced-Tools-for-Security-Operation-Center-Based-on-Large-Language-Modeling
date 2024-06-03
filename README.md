# Enhanced Tools for Security Operation Center Based on Large Language Modeling

## Equipment

- **GPU**: RTX 3070 Ti
- **CPU**: Intel i5-12400
- **Memory**: 32GB DDR4-3200
- **Operating System**: Windows 11
- **Torch Version**: 2.1.2+cu118

## Requirements Installation

To install the necessary requirements, use the following command:

```sh
pip install -r requirements.txt

## Overview

This project aims to integrate the BERT model with Ollama and Lily-Cybersecurity-7B-v0.2 using URLTran to develop a phishing URL detection and real-time monitoring system. By deploying the BERT model as a service, configuring PyShark to capture network traffic, and integrating the results into the existing system, we aim to achieve comprehensive real-time monitoring and phishing URL detection. This system will alert users if a malicious URL is accessed and offer detailed risk reports upon request.

## Introduction

Phishing attacks are a significant threat in today's digital landscape, and detecting these threats in real-time is crucial. This project aims to enhance phishing URL detection by leveraging transformer models, specifically BERT, combined with Ollama and Lily-Cybersecurity-7B-v0.2. Our system monitors user web activity, alerts on malicious URLs, and provides detailed risk analysis reports.

## Data Collection and Preprocessing

During the data collection phase, we faced challenges due to the unavailability of Phishing.Database. To overcome this, we sourced URLs from OpenPhish, PhishTank, Tranco, and Chrome browsing history, successfully compiling a dataset with over ten thousand URLs.

- Malicious URLs: 57,889
- Benign URLs: 60,158

## Masked Language Modeling (MLM.py)

Masked Language Modeling (MLM) is employed to pre-train the BERT model. This involves:

1. **Pre-training**: An unsupervised process where the model learns to predict hidden words in a given context, aiding in understanding language structure.
2. **Data Preparation**: Processing URL data by masking certain words for the model to predict.
3. **Training**: Using the masked data to train BERT, enabling it to learn URL language patterns.

After running MLM.PY, a pre-trained BERT model, understanding URL language structure, is obtained.

## Model Fine-Tuning (CLASSIFIER.py)

The fine-tuning model involves applying a pre-trained BERT model to a specific downstream task (such as phishing URL detection). This process includes the following steps:

1. **Loading the Pre-trained Model**: Using the BERT model trained in the Masked Language Modeling (MLM) step as the starting point.
2. **Data Preparation**: Loading the dataset labeled with phishing and non-phishing URLs and converting it into a format that the model can process.
3. **Training the Model**: Using these labeled data to fine-tune the BERT model, enabling it to distinguish between phishing and non-phishing URLs.

Running CLASSIFIER.PY will generate a fine-tuned BERT model specifically for phishing URL detection.

## Deploying Model Service (BERT_service.py) and Real-Time Monitoring (PYSHARK.py)

To implement the deployment of the model service along with real-time monitoring and URL classification, the following methods were employed:

1. **Initialize VirusTotal Client**: Initialize the VirusTotal client using `vt.Client(API_KEY)`.
2. **Extract URL and Obtain Report**: In the get_virustotal_report function, encode the URL in base64 and obtain the report from VirusTotal. Parse and format the information from the report.
3. **Real-time Monitoring and Interaction**: Use PyShark to monitor network traffic, extract URLs, and classify them using the local classification service. If a malicious URL is detected, call get_virustotal_report to get a detailed report and interact with the user to display the report content.

## Real-Time Monitoring Combining LLM (Combine.py)

In the previous chapter, PyShark.py was implemented for real-time monitoring, which only interacts with users to check if they want to view additional information upon detecting a malicious URL. The aim now is to enhance this functionality, enabling not only the generation of relevant data but also interactive dialogues with the user. This includes discussing countermeasures for malicious URLs, assisting in finding alternative URLs, providing protection strategies, solutions, and other related information.

## System Interface (SystemInterface.html)

To optimize the system interface, here are the specific implementation details:

1. Each detected URL will be placed in the Report section and visually separated for easy user viewing.
2. Ollama's responses should be based on each generated report. It is necessary to ensure that the content of the reports (information collected in the Report section) is correctly included in the model's context. In the /chat route, if there are recent reports, pass their content as context to the retrieval_chain.
3. Enhance the prompt template: Ensure the prompt template clearly instructs the model to generate responses based on the provided report content. Add \\n\\n---\\n\\n as a separator in the prompt template to indicate the model should automatically segment its responses.
4. Add a /get_reports_in_time_range route: This route will allow users to query the number of malicious URLs within a specific time range and compile a report.

## Performance Testing (Test.py)

The goal is to integrate Ollama into PyShark.py and enhance the detection and response capabilities for malicious URLs. During this process, performance testing needs to be conducted before and after integrating Ollama to compare the improvements. To achieve this goal, the following steps need to be taken:

1. Test the bert_service.py, which starts the Flask service, to evaluate the model's performance in classifying phishing and non-phishing URLs.
2. Integrate Ollama functionality into PyShark.py to achieve more intelligent interactions.
3. Retest the integrated system to compare the improved performance.

### Step 1: Testing bert_service.py

- Use DDDD.py to test the performance of the BERT model.
- Results: Accuracy = 0.662, Precision = 0.667, Recall = 0.986, F1 Score = 0.796.

### Step 2: Testing the Integrated System

- Use DDDD.py to test the system integrated with Ollama functionality, allowing for performance comparison before and after integration.
- Results: Accuracy = 0.662, Precision = 0.876, Recall = 0.95, F1 Score = 0.85.

## Advantages and Improvements

### Advantages

- **Significant Improvement in Precision**: The precision increased from 0.667 to 0.876, demonstrating a notable enhancement in correctly identifying phishing URLs after integrating Ollama.
- **High Recall Rate**: The recall rate remains high at 0.950 compared to 0.986 before integration, indicating that the system can still effectively detect most phishing URLs.
- **Increase in F1 Score**: The F1 score increased from 0.796 to 0.851, reflecting an overall improvement in both precision and recall.

### Disadvantages

- **No Significant Change in Accuracy**: The accuracy remained unchanged before and after integration, indicating that while precision and F1 score improved, the overall accuracy did not show significant enhancement.
- **Performance Overhead**: Integrating Ollama may increase system resource consumption, requiring further optimization to ensure stable operation in various environments.

### Future Optimization Directions

- **Refinement of Model Parameters**: Further adjust the parameters of Ollama and BERT models to enhance overall accuracy and efficiency.
- **Resource Optimization**: Optimize system resource usage to ensure performance stability in multi-task processing and high traffic data environments.
- **Real-time Monitoring and Adaptation**: Develop real-time monitoring and adaptive server allocation mechanisms to improve system response speed and accuracy.
- **Geographical Analysis Expansion**: Expand the analysis scope to include more regions, compare results across different areas, and identify optimization strategies.
- **Application of Advanced Machine Learning Algorithms**: Explore the use of more advanced machine learning algorithms to predict server demand and optimize allocations.

## Literature Review and References

In developing this project, the following studies were referenced:

1. Nourmohammadzadeh Motlagh, F., et al. (2024). Large Language Models in Cybersecurity: State-of-the-Art. arXiv preprint arXiv:2402.00891, [DOI:10.48550/arXiv.2402.00891](https://doi.org/10.48550/arXiv.2402.00891)
2. Maneriker, P., et al. (2021). URLTran: Improving Phishing URL Detection Using Transformers. arXiv preprint arXiv:2106.05256, [DOI:10.48550/arXiv.2106.05256](https://doi.org/10.48550/arXiv.2106.05256)
3. [BERT base model (uncased)](https://huggingface.co/google-bert/bert-base-uncased)
4. [VirusTotal Python Library (vt-py)](https://github.com/VirusTotal/vt-py?tab=readme-ov-file)
5. [PhiUSIL Phishing URL Dataset](https://archive.ics.uci.edu/dataset/967/phiusil-phishing-url-dataset)
6. [URLTran: Improving Phishing URL Detection via Transformers](https://github.com/bfilar/URLTran)
7. [PyShark: Python wrapper for Tshark, the network traffic analyzer](https://github.com/KimiNewt/pyshark)
