import torch
from sklearn.metrics import accuracy_score, f1_score
from torch.utils.data import DataLoader, Dataset
from transformers import AutoConfig, AutoModelForSequenceClassification, BertTokenizer
from models.data import data_prep
from tqdm import tqdm
import logging
import pandas as pd

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


model_ckpt = "models/URLTran-BERT-1"
config = AutoConfig.from_pretrained(model_ckpt)
config.num_labels = 2
config.problem_type = "single_label_classification"

tokenizer = BertTokenizer.from_pretrained(model_ckpt)
model = AutoModelForSequenceClassification.from_pretrained(model_ckpt, config=config)

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

class URLTranDataset(Dataset):
    def __init__(self, csv_file, tokenizer):
        self.data = pd.read_csv(csv_file)
        self.tokenizer = tokenizer
        self.encodings = data_prep.preprocess(self.data['url'].tolist(), tokenizer)
        self.labels = self.data['label'].tolist()

    def __getitem__(self, idx):
        item = {key: val[idx].clone().detach() for key, val in self.encodings.items()}
        item['label'] = torch.tensor(self.labels[idx]).clone().detach()
        return item

    def __len__(self):
        return len(self.labels)

def predict(url, tokenizer, model):
    inputs = data_prep.preprocess([url], tokenizer)
    return torch.argmax(torch.softmax(model(**inputs).logits, dim=1)).tolist()

def train_model(train_dataset, model):
    train_loader = DataLoader(train_dataset, batch_size=128, shuffle=True)
    model.to(device)
    model.train()
    optimizer = torch.optim.AdamW(model.parameters(), lr=1e-4)
    epochs = 10
    for epoch in range(epochs):
        logging.info(f"Starting epoch {epoch + 1}/{epochs}")
        total_loss = 0
        progress_bar = tqdm(enumerate(train_loader), total=len(train_loader), desc=f"Epoch {epoch + 1}")
        for step, batch in progress_bar:
            optimizer.zero_grad()
            inputs = batch["input_ids"].to(device)
            attention_mask = batch["attention_mask"].to(device)
            labels = batch["label"].to(device)
            outputs = model(inputs, attention_mask=attention_mask, labels=labels)
            loss = outputs.loss
            loss.backward()
            optimizer.step()
            total_loss += loss.item()
            progress_bar.set_postfix(loss=loss.item())
        avg_loss = total_loss / len(train_loader)
        logging.info(f"Epoch {epoch + 1} completed. Average Loss: {avg_loss}")
        model.save_pretrained(f"finetuned_model/epoch-{epoch}")
        tokenizer.save_pretrained(f"finetuned_model/epoch-{epoch}")
    logging.info("Training completed")

def eval_model(eval_dataset, tokenizer, model):
    eval_loader = DataLoader(eval_dataset, batch_size=2000, shuffle=True)
    y_true = []
    y_pred = []
    model.eval()
    with torch.no_grad():
        for batch in eval_loader:
            inputs = batch["input_ids"].to(device)
            labels = batch["label"].to(device)
            outputs = model(inputs, attention_mask=batch["attention_mask"].to(device), labels=labels)
            predictions = [
                torch.argmax(pred).tolist()
                for pred in torch.softmax(outputs.logits, dim=1)
            ]
            y_true.extend(labels.tolist())
            y_pred.extend(predictions)
        total_acc = accuracy_score(y_true, y_pred)
        total_f1 = f1_score(y_true, y_pred)
        logging.info(f"Accuracy: {total_acc}")
        logging.info(f"F1 Score: {total_f1}")

if __name__ == "__main__":
    data_path = "data/final_data.csv"
    dataset = URLTranDataset(data_path, tokenizer)
    train_model(dataset, model)
