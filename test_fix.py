from backend.app.scanner.classifier import PIIDetector, PIIClassification, DetectionReason

detector = PIIDetector()

# Test email
result = detector.classify_by_sample_values(['user@example.com', 'test@gmail.com'])
print(f'Email: cls={result[0]}, conf={result[1]}')

# Test credit card
result = detector.classify_by_sample_values(['4111111111111111', '5500000000000004'])
print(f'Credit card: cls={result[0]}, conf={result[1]}')

# Test PAN
result = detector.classify_by_sample_values(['ABCDE1234F', 'PANEL0987A'])
print(f'PAN: cls={result[0]}, conf={result[1]}')

# Test Aadhaar
result = detector.classify_by_sample_values(['123456789012', '987654321098'])
print(f'Aadhaar: cls={result[0]}, conf={result[1]}')

# Test SSN
result = detector.classify_by_sample_values(['123-45-6789', '987-65-4321'])
print(f'SSN: cls={result[0]}, conf={result[1]}')

# Test phone
result = detector.classify_by_sample_values(['9876543210', '6123456789'])
print(f'Phone: cls={result[0]}, conf={result[1]}')

# Test account number
result = detector.classify_by_sample_values(['12345678', '98765432101234567'])
print(f'Account number: cls={result[0]}, conf={result[1]}')

# Test salary
result = detector.classify_by_sample_values(['$50000', '50000.00', '50000'])
print(f'Salary: cls={result[0]}, conf={result[1]}')

# Test invalid
result = detector.classify_by_sample_values(['hello', 'world', 'test'])
print(f'No PII: {result}')