from backend.app.scanner.pii_detector import PIIDetector, PIIScanResult
from backend.app.scanner.classifier import PIIClassification

detector = PIIDetector()
result = detector.scan_column("email", ["user1@example.com", "user2@example.com"])
print("Result type:", type(result))
print("Result classification:", result.classification, "type:", type(result.classification))
print("Result classification.name:", result.classification.name)
print("Result[\"classification\"]:", result["classification"])