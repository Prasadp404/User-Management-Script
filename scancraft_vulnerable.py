# scancraft_vulnerable.py - VULNERABLE PORT SCANNER APPLICATION

from flask import Flask, request, jsonify, render_template_string
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

app = Flask(__name__)
socket.setdefaulttimeout(0.5)

# VULNERABILITY 1: Hardcoded Secrets
API_KEY = "Eric"
ADMIN_PASSWORD = "ERIC123"

HTML_PAGE = """
<!DOCTYPE html>
<html>
<head>
  <title>ScanCraft - Network Port Scanner</title>
  <style>
    body { font-family: Arial; padding: 20px; background: #f5f5f5; }
    .container { max-width: 600px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
    h1 { color: #333; }
    input { margin: 5px 0; padding: 10px; width: 100%; box-sizing: border-box; border: 1px solid #ddd; border-radius: 4px; }
    button { padding: 12px 24px; margin: 10px 5px 10px 0; cursor: pointer; background: #007bff; color: white; border: none; border-radius: 4px; }
    button:hover { background: #0056b3; }
    #results { margin-top: 20px; padding: 15px; background: #f8f9fa; border-radius: 4px; min-height: 50px; }
    .info { color: #666; font-size: 14px; margin-top: 20px; padding: 10px; background: #fff3cd; border-radius: 4px; }
    
  </style>
</head>
<body>
  <div class="container">
    <h1> ScanCraft</h1>
    <p>Network Port Scanner Tool</p>

    <div>
      <input id="ip" placeholder="IP Address or Hostname" >
      <input id="start" placeholder="Start Port" type="text">
      <input id="end" placeholder="End Port" type="text">
      <button onclick="scan()"> Scan Ports</button>
    </div>
         
    <div id="results"></div>
    
  </div>

<script>
function scan(){
  // VULNERABILITY 1: API key hardcoded in client-side JavaScript
  fetch("/scan", {
    method: "POST",
    headers: {
      "Content-Type":"application/json",
      "X-API-KEY":"Eric"
    },
    body: JSON.stringify({
      ipAddress: ip.value,
      startPort: start.value,
      endPort: end.value
    })
  })
  .then(r => r.json())
  .then(d => {
    let out = "<h3>Scan Results:</h3>";
    if(d.error){
      out += "<p style='color:red;'>Error: " + d.error + "</p>";
    }
    if(d.results && d.results.length > 0){
      out += "<ul style='list-style: none; padding: 0;'>";
      d.results.forEach(p=>{
        out += "<li style='padding: 5px; background: #d4edda; margin: 5px 0; border-radius: 4px;'>✓ Port " + p.port + " - <strong>OPEN</strong></li>";
      });
      out += "</ul>";
    } else if(d.results && d.results.length === 0) {
      out += "<p>No open ports found in the specified range.</p>";
    }
    document.getElementById("results").innerHTML = out;
  })
  .catch(e => {
    document.getElementById("results").innerHTML = "<p style='color:red;'>Error: " + e + "</p>";
  });
}
</script>
</body>
</html>
"""

def scan_port(ip, port):
    """Scan a single port"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = s.connect_ex((ip, int(port)))
        s.close()
        if result == 0:
            return port
    except Exception as e:
        pass
    return None

@app.route("/")
def home():
    return render_template_string(HTML_PAGE)

@app.route("/scan", methods=["POST"])
def scan():
    # VULNERABILITY 2: Weak Authentication - Single shared API key
    api_key = request.headers.get("X-API-KEY")
    if not api_key or api_key != API_KEY:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json()
    
    # VULNERABILITY 3: Lack of Input Validation
    # No IP address format validation
    ip = data.get("ipAddress")
    start_port = data.get("startPort")
    end_port = data.get("endPort")
    
    # Minimal validation - accepts almost anything
    if not ip:
        return jsonify({"error": "IP address required"}), 400
    
    # VULNERABILITY 3: No proper validation on port numbers
    # No range limits, no type checking
    try:
        start = int(start_port)
        end = int(end_port)
    except:
        return jsonify({"error": "Invalid port numbers"}), 400
    
    # No checks for:
    # - Negative numbers
    # - start > end
    # - Excessive range (DoS protection)
    # - Valid port range (1-65535)
    
    results = []
    
    # Scan ports
    try:
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(scan_port, ip, p) for p in range(start, end + 1)]
            for future in as_completed(futures):
                port = future.result()
                if port:
                    results.append({"port": port})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
    return jsonify({"results": results})

@app.route("/config")
def config():
    # VULNERABILITY 1 & 2: Exposing hardcoded secrets without authentication
    import os
    return jsonify({
        "api_key": API_KEY,
        "admin_password": ADMIN_PASSWORD,
        "debug": app.config.get('DEBUG', False),
        "python_version": os.sys.version
    })

if __name__ == "__main__":
    # VULNERABILITY 4: Missing HTTPS
    # Application runs on HTTP without SSL/TLS encryption
    # All data transmitted in plain text including API keys
    app.run(host="0.0.0.0", port=3000, debug=True)