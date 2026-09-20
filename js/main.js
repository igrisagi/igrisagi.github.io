// --- Canvas Network Animation ---
const canvas = document.getElementById('networkCanvas');
const ctx = canvas.getContext('2d');

let width, height, particles;

function initCanvas() {
    width = canvas.width = window.innerWidth;
    height = canvas.height = window.innerHeight;
    particles = [];
    
    const numParticles = Math.floor((width * height) / 15000);
    
    for(let i = 0; i < numParticles; i++) {
        particles.push({
            x: Math.random() * width,
            y: Math.random() * height,
            vx: (Math.random() - 0.5) * 0.5,
            vy: (Math.random() - 0.5) * 0.5,
            radius: Math.random() * 1.5 + 0.5
        });
    }
}

function drawNetwork() {
    ctx.clearRect(0, 0, width, height);
    
    // Update and draw particles
    particles.forEach(p => {
        p.x += p.vx;
        p.y += p.vy;
        
        // Bounce off edges
        if (p.x < 0 || p.x > width) p.vx *= -1;
        if (p.y < 0 || p.y > height) p.vy *= -1;
        
        ctx.beginPath();
        ctx.arc(p.x, p.y, p.radius, 0, Math.PI * 2);
        ctx.fillStyle = 'rgba(0, 240, 255, 0.5)';
        ctx.fill();
    });
    
    // Draw connections
    for(let i = 0; i < particles.length; i++) {
        for(let j = i + 1; j < particles.length; j++) {
            const dx = particles[i].x - particles[j].x;
            const dy = particles[i].y - particles[j].y;
            const dist = Math.sqrt(dx * dx + dy * dy);
            
            if (dist < 150) {
                ctx.beginPath();
                ctx.moveTo(particles[i].x, particles[i].y);
                ctx.lineTo(particles[j].x, particles[j].y);
                ctx.strokeStyle = `rgba(0, 240, 255, ${0.2 - dist/750})`;
                ctx.stroke();
            }
        }
    }
    
    requestAnimationFrame(drawNetwork);
}

window.addEventListener('resize', initCanvas);
initCanvas();
drawNetwork();

// --- Typewriter Effect ---
const phrases = [
    "Building conscious machines.",
    "Solving the alignment problem.",
    "Designing next-gen neural architectures.",
    "Advancing artificial general intelligence."
];

let phraseIndex = 0;
let charIndex = 0;
let isDeleting = false;
const typewriterElement = document.getElementById('typewriter');

function type() {
    const currentPhrase = phrases[phraseIndex];
    
    if (isDeleting) {
        typewriterElement.textContent = currentPhrase.substring(0, charIndex - 1);
        charIndex--;
    } else {
        typewriterElement.textContent = currentPhrase.substring(0, charIndex + 1);
        charIndex++;
    }
    
    let typeSpeed = isDeleting ? 30 : 70;
    
    if (!isDeleting && charIndex === currentPhrase.length) {
        typeSpeed = 2000; // Pause at end
        isDeleting = true;
    } else if (isDeleting && charIndex === 0) {
        isDeleting = false;
        phraseIndex = (phraseIndex + 1) % phrases.length;
        typeSpeed = 500; // Pause before new word
    }
    
    setTimeout(type, typeSpeed);
}
setTimeout(type, 1000);

// --- Scroll Fade In Observer ---
const observerOptions = {
    root: null,
    rootMargin: '0px',
    threshold: 0.1
};

const observer = new IntersectionObserver((entries, observer) => {
    entries.forEach(entry => {
        if (entry.isIntersecting) {
            entry.target.classList.add('visible');
            observer.unobserve(entry.target);
        }
    });
}, observerOptions);

document.querySelectorAll('.fade-in').forEach(el => {
    observer.observe(el);
});

// --- Terminal Simulation ---
const terminalLines = [
    "> Initialize AGI core ... [OK]",
    "> Loading neural weights ... 100%",
    "> Bootstrapping cognitive engine ...",
    "> Establishing alignment protocols ... [VERIFIED]",
    "> Warning: Consciousness emergent property detected.",
    "> Analyzing parameters...",
    "> System online. Waiting for input..."
];

const terminalOutput = document.getElementById('terminal-output');
let termLineIdx = 0;

function printTerminalLine() {
    if (termLineIdx < terminalLines.length) {
        const p = document.createElement('div');
        p.textContent = terminalLines[termLineIdx];
        terminalOutput.appendChild(p);
        termLineIdx++;
        setTimeout(printTerminalLine, Math.random() * 800 + 200);
    } else {
        const cursorP = document.createElement('div');
        cursorP.innerHTML = 'root@erenlabs:~# <span class="cursor">_</span>';
        terminalOutput.appendChild(cursorP);
    }
}

// Start terminal simulation when scrolled into view
const termObserver = new IntersectionObserver((entries) => {
    if (entries[0].isIntersecting) {
        setTimeout(printTerminalLine, 500);
        termObserver.disconnect();
    }
});
termObserver.observe(document.getElementById('terminal'));

