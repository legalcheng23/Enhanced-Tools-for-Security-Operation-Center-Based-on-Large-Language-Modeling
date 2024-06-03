import torch
from torch.utils.data import DataLoader, Dataset
from transformers import BertForMaskedLM, BertTokenizer
from models.data import data_prep
from tqdm import tqdm
import logging
import pandas as pd

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

tokenizer = BertTokenizer.from_pretrained("bert-base-uncased")
model = BertForMaskedLM.from_pretrained("bert-base-uncased")

class URLTranDataset(Dataset):
    def __init__(self, csv_file, tokenizer):
        self.data = pd.read_csv(csv_file)
        self.tokenizer = tokenizer
        self.encodings = data_prep.preprocess(self.data['url'].tolist(), tokenizer)
        self.labels = self.data['label'].tolist()

    def __getitem__(self, idx):
        # item = {key: torch.tensor(val[idx]) for key, val in self.encodings.items()}
        # item['label'] = torch.tensor(self.labels[idx])
        item = {key: val[idx].clone().detach() for key, val in self.encodings.items()}
        item['label'] = torch.tensor(self.labels[idx]).clone().detach()
        return item

    def __len__(self):
        return len(self.labels)

def train(dataset, model):
    loader = DataLoader(dataset, batch_size=32, shuffle=True)
    model.to(device)
    model.train()
    optimizer = torch.optim.AdamW(model.parameters(), lr=2e-5)

    epochs = 2
    for epoch in range(epochs):
        logging.info(f"Starting epoch {epoch + 1}/{epochs}")
        total_loss = 0
        progress_bar = tqdm(enumerate(loader), total=len(loader), desc=f"Epoch {epoch + 1}")
        for step, batch in progress_bar:
            optimizer.zero_grad()
            masked_inputs = data_prep.masking_step(batch["input_ids"]).to(device)
            attention_mask = batch["attention_mask"].to(device)
            labels = batch["mlm_labels"].to(device)
            outputs = model(masked_inputs, attention_mask=attention_mask, labels=labels)
            loss = outputs.loss
            loss.backward()
            optimizer.step()
            total_loss += loss.item()
            progress_bar.set_postfix(loss=loss.item())
        avg_loss = total_loss / len(loader)
        logging.info(f"Epoch {epoch + 1} completed. Average Loss: {avg_loss}")
        model.save_pretrained(f"models/URLTran-BERT-{epoch}")
        tokenizer.save_pretrained(f"models/URLTran-BERT-{epoch}")
    logging.info("MLM training completed")

def predict_mask(url, tokenizer, model):
    inputs = data_prep.preprocess([url], tokenizer) 
    masked_inputs = data_prep.masking_step(inputs["input_ids"]).to(device)
    attention_mask = inputs["attention_mask"].to(device)
    with torch.no_grad():
        predictions = model(masked_inputs, attention_mask=attention_mask)
    output_ids = torch.argmax(predictions.logits, dim=-1).tolist()
    return masked_inputs.cpu().tolist(), output_ids

if __name__ == "__main__":
    logging.info("Starting MLM training")
    data_path = "data/final_data.csv"
    dataset = URLTranDataset(data_path, tokenizer) 
    train(dataset, model)
    logging.info("MLM training completed")

    # Example Inference
    url = "huggingface.co/docs/transformers/task_summary"
    input_ids, output_ids = predict_mask(url, tokenizer, model)
    logging.info(f"input_ids: {input_ids}")
    logging.info(f"output_ids: {output_ids}")


    masked_input = "".join(tokenizer.convert_ids_to_tokens(input_ids[0], skip_special_tokens=True)).replace("##", "")
    prediction = "".join(tokenizer.convert_ids_to_tokens(output_ids[0], skip_special_tokens=True)).replace("##", "")
    logging.info(f"Masked Input: {masked_input}")
    logging.info(f"Predicted Output: {prediction}")
