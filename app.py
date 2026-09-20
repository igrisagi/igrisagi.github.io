from flask import Flask, render_template, jsonify
import random
import time

app = Flask(__name__)

# Simulated dynamic database for AGI Research
research_projects = [
    {"id": 1, "title": "Neural-Symbolic Integration", "status": "Active", "progress": 87},
    {"id": 2, "title": "Autonomous Agents", "status": "Testing", "progress": 92},
    {"id": 3, "title": "Alignment & Safety", "status": "Review", "progress": 75},
    {"id": 4, "title": "Cognitive Architectures", "status": "Active", "progress": 60}
]

@app.route('/')
def home():
    # Pass dynamic data to the HTML template
    return render_template('index.html', projects=research_projects, server_time=time.strftime('%Y-%m-%d %H:%M:%S'))

@app.route('/api/system_status')
def system_status():
    # Dynamic API endpoint returning live metrics
    return jsonify({
        "cpu_usage": round(random.uniform(20.0, 85.0), 2),
        "memory_usage": round(random.uniform(40.0, 95.0), 2),
        "active_nodes": random.randint(100, 500),
        "status": "Optimal"
    })

if __name__ == '__main__':
    app.run(debug=True, port=8000)
