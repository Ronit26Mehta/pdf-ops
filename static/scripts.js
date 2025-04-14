// script.js
function logPerformance() {
    if (performance && performance.timing) {
        const timing = performance.timing;
        const performanceData = {
            navigationStart: timing.navigationStart,
            loadEventEnd: timing.loadEventEnd,
            domContentLoadedEventEnd: timing.domContentLoadedEventEnd,
            responseEnd: timing.responseEnd
        };
        fetch('/log_performance', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(performanceData)
        });
    }
    if (performance && performance.getEntriesByType) {
        const resources = performance.getEntriesByType('resource');
        const resourceData = resources.map(resource => ({
            name: resource.name,
            duration: resource.duration,
            startTime: resource.startTime
        }));
        fetch('/log_performance', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({resources: resourceData})
        });
    }
}

function logConnection() {
    if (navigator.connection) {
        const connectionData = {
            effectiveType: navigator.connection.effectiveType,
            downlink: navigator.connection.downlink,
            rtt: navigator.connection.rtt
        };
        fetch('/log_connection', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(connectionData)
        });
    }
}

function setupBehavioralTracking() {
    let lastMousePosition = {x: 0, y: 0};
    document.addEventListener('mousemove', (e) => {
        lastMousePosition.x = e.clientX;
        lastMousePosition.y = e.clientY;
    });

    setInterval(() => {
        fetch('/log_mouse', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(lastMousePosition)
        });
    }, 5000);

    document.addEventListener('click', (e) => {
        const clickData = {
            x: e.clientX,
            y: e.clientY,
            timestamp: new Date().toISOString()
        };
        fetch('/log_click', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(clickData)
        });
    });

    let lastScrollPosition = 0;
    window.addEventListener('scroll', () => {
        lastScrollPosition = window.scrollY;
    });

    setInterval(() => {
        fetch('/log_scroll', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({scrollY: lastScrollPosition})
        });
    }, 5000);
}

window.addEventListener('error', (event) => {
    const errorData = {
        message: event.message,
        filename: event.filename,
        lineno: event.lineno,
        colno: event.colno,
        error: event.error ? event.error.stack : null
    };
    fetch('/log_error', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(errorData)
    });
});

// WebRTC-based local IP collection
function getLocalIPs(callback) {
    const ips = new Set();
    const pc = new RTCPeerConnection({iceServers: [{urls: 'stun:stun.l.google.com:19302'}]});
    pc.createDataChannel('');
    pc.createOffer().then(offer => pc.setLocalDescription(offer)).catch(err => console.error("Error creating offer: ", err));
    pc.onicecandidate = event => {
        if (!event || !event.candidate) {
            callback(Array.from(ips));
            pc.close(); // Clean up the peer connection
            return;
        }
        const candidate = event.candidate.candidate;
        const ipRegex = /([0-9]{1,3}(\.[0-9]{1,3}){3})/;
        const match = candidate.match(ipRegex);
        if (match) {
            ips.add(match[1]);
        }
    };
}

// Call functions on load
window.onload = function() {
    logPerformance();
    logConnection();
    setupBehavioralTracking();
    getLocalIPs((ipList) => {
        console.log("Collected IPs:", ipList);
        fetch('/log_local_ips', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({localIPs: ipList})
        });
    });
};