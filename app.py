#!/usr/bin/env python3
"""Flask backend for MWP Obfuscator website.
Usage: python app.py
Then open http://localhost:5000
"""
from flask import Flask, request, jsonify, send_from_directory
import subprocess, tempfile, os, sys, threading

app = Flask(__name__, static_folder='.', static_url_path='')
OBF = os.path.join(os.path.dirname(__file__), 'obf.py')
MAX_SOURCE_BYTES = int(os.environ.get('MWP_MAX_SOURCE_BYTES', 200_000))
MAX_OUTPUT_BYTES = int(os.environ.get('MWP_MAX_OUTPUT_BYTES', 4_000_000))
MAX_CONCURRENT_JOBS = int(os.environ.get('MWP_MAX_CONCURRENT_JOBS', 2))
API_TOKEN = os.environ.get('MWP_API_TOKEN')
jobs = threading.BoundedSemaphore(MAX_CONCURRENT_JOBS)

@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

@app.route('/obfuscate', methods=['POST'])
def obfuscate():
    if API_TOKEN and request.headers.get('Authorization') != f'Bearer {API_TOKEN}':
        return jsonify({'error': 'Unauthorized'}), 401
    if request.content_length and request.content_length > MAX_SOURCE_BYTES + 4096:
        return jsonify({'error': 'Request is too large'}), 413
    try:
        data = request.get_json(force=True) or {}
    except Exception:
        return jsonify({'error': 'Invalid JSON'}), 400

    code = data.get('code', '')
    if not code:
        return jsonify({'error': 'No Lua code provided'}), 400
    if not isinstance(code, str) or len(code.encode('utf-8')) > MAX_SOURCE_BYTES:
        return jsonify({'error': f'Source exceeds the {MAX_SOURCE_BYTES}-byte limit'}), 413

    seed = data.get('seed')
    double = bool(data.get('double', False))
    target = data.get('target', 'luau')
    anti_debug = bool(data.get('anti_debug', False))
    if target not in ('luau', 'lua51'):
        return jsonify({'error': 'target must be "luau" or "lua51"'}), 400
    if double and target != 'lua51':
        return jsonify({'error': 'Double wrapping requires target "lua51"'}), 400
    if seed is not None:
        try:
            seed = int(seed)
        except (TypeError, ValueError):
            return jsonify({'error': 'seed must be an integer'}), 400
    if not jobs.acquire(blocking=False):
        return jsonify({'error': 'Server is busy; retry shortly'}), 429

    fd_in, tmp_in = tempfile.mkstemp(suffix='.lua')
    tmp_out = tmp_in.replace('.lua', '.obf.lua')
    try:
        with os.fdopen(fd_in, 'w', encoding='utf-8') as f:
            f.write(code)

        cmd = [sys.executable, OBF, tmp_in, tmp_out]
        if seed is not None:
            cmd += ['--seed', str(seed)]
        if double:
            cmd.append('--double')
        cmd += ['--target', target]
        if anti_debug:
            cmd.append('--anti-debug')

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            err = (result.stderr or result.stdout or 'Compilation failed').strip()
            return jsonify({'error': err}), 422

        with open(tmp_out, encoding='utf-8') as f:
            output = f.read()
        if len(output.encode('utf-8')) > MAX_OUTPUT_BYTES:
            return jsonify({'error': 'Obfuscated output exceeds the server output limit'}), 413

        return jsonify({'output': output, 'size_in': len(code), 'size_out': len(output)})
    except subprocess.TimeoutExpired:
        return jsonify({'error': 'Timed out (30s)'}), 504
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        for p in (tmp_in, tmp_out):
            try:
                if os.path.exists(p): os.remove(p)
            except OSError:
                pass
        jobs.release()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print(f'[MWP] Starting on http://localhost:{port}')
    app.run(host=os.environ.get('MWP_HOST', '127.0.0.1'), port=port, debug=False)
