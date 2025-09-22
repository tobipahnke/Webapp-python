from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash
import random
import string
import base64
import smtplib
import yara
import os
from email.message import EmailMessage

app = Flask(__name__, static_url_path='/passgen/static', static_folder='static')

# Yara Rule Directory
YARA_RULES_DIR = '/var/www/passgen/yara_rules'

@app.route('/passgen/')
def index():
    return render_template('index.html')

@app.route('/passgen/generate', methods=['POST'])
def generate():
    data = request.get_json()
    length = int(data.get('length', 12))
    complexity = data.get('complexity', 'medium')
    exclude_list = data.get('exclude', [])

    if length < 4 or length > 128:
        return jsonify({'error': 'Ungültige Passwortlänge'}), 400

    if complexity == 'low':
        chars = string.ascii_lowercase
    elif complexity == 'medium':
        chars = string.ascii_letters + string.digits
    else: 
        base_chars = string.ascii_letters + string.digits
        specials = ''.join(c for c in string.punctuation if c not in exclude_list)
        chars = base_chars + specials

    if not chars:
        return jsonify({'error': 'Zeichenmenge ist leer nach Ausschluss'}), 400

    password = ''.join(random.choice(chars) for _ in range(length))
    return jsonify({'password': password})


@app.route('/base/')
def base64_index():
    return render_template('base64.html')

@app.route('/base/convert', methods=['POST'])
def base64_convert():
    data = request.get_json()
    action = data.get('action')
    text = data.get('text', '')

    try:
        if action == 'encode':
            result = base64.b64encode(text.encode()).decode()
        elif action == 'decode':
            result = base64.b64decode(text.encode()).decode()
        else:
            return jsonify({'error': 'Ungültige Aktion'}), 400
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': f'Ungültige Eingabe: {str(e)}'}), 400

@app.route('/')
def dashboard():
    return render_template('dashboard.html')

@app.route('/yara/')
def yara_index():
    rule_files = [f for f in os.listdir(YARA_RULES_DIR) if f.endswith('.yar') or f.endswith('.yara')]
    return render_template('yara_dashboard.html', rules=rule_files)

@app.route('/yara/check', methods=['POST'])
def yara_check():
    file = request.files['file']
    filepath = os.path.join('/tmp', file.filename)
    file.save(filepath)

    try:
        compiled_rules = yara.compile(filepath=os.path.join(YARA_RULES_DIR, 'all_rules.yar'))
        matches = compiled_rules.match(filepath)
        os.remove(filepath)
        return render_template('yara_result.html', matches=matches)
    except Exception as e:
        os.remove(filepath)
        return f'Fehler bei YARA: {str(e)}', 400

@app.route('/yara/test-rule', methods=['GET', 'POST'])
def yara_test_rule():
    if request.method == 'POST':
        if 'rulefile' not in request.files or 'targetfile' not in request.files:
            return 'Beide Dateien müssen hochgeladen werden.', 400

        rule_file = request.files['rulefile']
        target_file = request.files['targetfile']

        import uuid
        import tempfile

        rule_path = f"/tmp/{uuid.uuid4().hex}.yar"
        target_path = f"/tmp/{uuid.uuid4().hex}.bin"

        rule_file.save(rule_path)
        target_file.save(target_path)

        try:
            compiled = yara.compile(filepath=rule_path)
            matches = compiled.match(filepath=target_path)
            return render_template('yara_result.html', matches=matches)
        except Exception as e:
            return f"Fehler beim Testen der Regel: {str(e)}", 400
        finally:
            if os.path.exists(rule_path): os.remove(rule_path)
            if os.path.exists(target_path): os.remove(target_path)

    return render_template('yara_test_rule.html')


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
