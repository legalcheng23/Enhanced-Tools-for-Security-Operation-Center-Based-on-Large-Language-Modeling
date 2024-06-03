from flask import Flask, request, jsonify
from transformers import BertTokenizer, BertForSequenceClassification
import torch

app = Flask(__name__)


tokenizer = BertTokenizer.from_pretrained('./finetuned_model/epoch-0') 
model = BertForSequenceClassification.from_pretrained('./finetuned_model/epoch-0')

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
model.to(device)

@app.route('/classify', methods=['POST'])
def classify_url():
    data = request.json
    url = data['url']
    inputs = tokenizer(url, return_tensors='pt', truncation=True, padding='max_length', max_length=128)
    inputs = {key: val.to(device) for key, val in inputs.items()}
    with torch.no_grad():
        outputs = model(**inputs)
    predictions = torch.argmax(outputs.logits, dim=-1).item()
    return jsonify({'classification': predictions})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
