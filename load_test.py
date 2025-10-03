from locust import HttpUser, task, between

# Paste your JWT token here
JWT_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoieW91cl91c2VyIiwicGVybWlzc2lvbnMiOlsicmVhZCIsImFuYWx5emUiXSwiZXhwIjoxNzU5MDA4Mzg5LCJpYXQiOjE3NTg5MjE5ODl9.UK-2wfV8naXEVuXbjACIenWXwA3BixQMnd5VqR3_s9g"

HEADERS = {
    "Authorization": f"Bearer {JWT_TOKEN}",
    "Content-Type": "application/json",
}

# Adjust payload to your API needs
SAMPLE_PAYLOAD = {
    "threat_id": "test123",
    "log_data": "Example log data for testing",
    "source_ip": "192.168.0.1",
    "metadata": {}
}

class ThreatAPILoadTest(HttpUser):
    # Random wait between requests to prevent server overload
    wait_time = between(1, 3)

    @task(2)
    def get_threats(self):
        self.client.get("/api/v1/threats/", headers=HEADERS)

    @task(3)
    def analyze_threat(self):
        self.client.post("/api/v1/threats/analyze", headers=HEADERS, json=SAMPLE_PAYLOAD)
