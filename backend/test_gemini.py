from google import genai

client = genai.Client(api_key="AIzaSyAx9-gHM-_dfyJAeNZur-VTPMjn4H59mdQ")

models = client.models.list()

for m in models:
    print(m.name)
