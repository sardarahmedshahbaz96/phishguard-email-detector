from flask import Flask, render_template, request, jsonify
from phishing_detector import PhishingDetector

app = Flask(__name__, template_folder='.', static_folder='.')

@app.route('/')
def home():
    # Serves your index.html file
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.get_json()
    email_content = data.get('email', '')
    
    if not email_content.strip():
        return jsonify({'error': 'No content provided'}), 400
        
    # Run your existing analysis engine
    detector = PhishingDetector(email_content)
    score, issues = detector.analyze()
    risk_level = detector.get_risk_level()
    
    return jsonify({
        'score': score,
        'risk_level': risk_level,
        'issues': issues
    })

if __name__ == '__main__':
    app.run(debug=True, port=5000)