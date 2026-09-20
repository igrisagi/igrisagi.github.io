const canvas = document.getElementById('networkCanvas');
const ctx = canvas.getContext('2d');
let width, height, particles;
function initCanvas() {
    width = canvas.width = window.innerWidth;
    height = canvas.height = window.innerHeight;
    particles = [];
    for(let i = 0; i < 100; i++) {
        particles.push({
            x: Math.random() * width, y: Math.random() * height,
            vx: (Math.random() - 0.5) * 0.5, vy: (Math.random() - 0.5) * 0.5,
            radius: Math.random() * 1.5 + 0.5
        });
    }
}
function drawNetwork() {
    ctx.clearRect(0, 0, width, height);
    particles.forEach(p => {
        p.x += p.vx; p.y += p.vy;
        if (p.x < 0 || p.x > width) p.vx *= -1;
        if (p.y < 0 || p.y > height) p.vy *= -1;
        ctx.beginPath(); ctx.arc(p.x, p.y, p.radius, 0, Math.PI * 2);
        ctx.fillStyle = 'rgba(0, 240, 255, 0.5)'; ctx.fill();
    });
    for(let i = 0; i < particles.length; i++) {
        for(let j = i + 1; j < particles.length; j++) {
            const dist = Math.hypot(particles[i].x - particles[j].x, particles[i].y - particles[j].y);
            if (dist < 150) {
                ctx.beginPath(); ctx.moveTo(particles[i].x, particles[i].y); ctx.lineTo(particles[j].x, particles[j].y);
                ctx.strokeStyle = `rgba(0, 240, 255, ${0.2 - dist/750})`; ctx.stroke();
            }
        }
    }
    requestAnimationFrame(drawNetwork);
}
window.addEventListener('resize', initCanvas);
initCanvas(); drawNetwork();

// Dynamic API fetch
async function updateMetrics() {
    try {
        const res = await fetch('/api/system_status');
        const data = await res.json();
        document.getElementById('metrics-output').innerHTML = `
            <br>> CPU Usage: ${data.cpu_usage}%
            <br>> Memory Usage: ${data.memory_usage}%
            <br>> Active Nodes: ${data.active_nodes}
            <br>> Status: ${data.status}
            <br><br>root@azure-server:~# <span class="cursor">_</span>
        `;
    } catch (e) {
        document.getElementById('metrics-output').innerHTML = "<br>> Error connecting to dynamic backend. Is it running?<br>> root@azure-server:~# _";
    }
}
setInterval(updateMetrics, 2000);
updateMetrics();
