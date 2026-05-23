from google import genai

client = genai.Client(api_key="Add API key ")

models = client.models.list()

for m in models:
    print(m.name)
