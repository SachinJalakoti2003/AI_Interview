// Camera functionality for interview practice
let currentStream = null;
let availableCameras = [];
let currentCameraIndex = 0;
let recordingStartTime = null;
let timerInterval = null;

// Initialize camera functionality when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    initializeCameraControls();
    requestCameraPermission();
});

function initializeCameraControls() {
    const startBtn = document.getElementById('startCameraBtn');
    const stopBtn = document.getElementById('stopCameraBtn');
    const toggleBtn = document.getElementById('toggleCameraBtn');

    if (startBtn) startBtn.addEventListener('click', startCamera);
    if (stopBtn) stopBtn.addEventListener('click', stopCamera);
    if (toggleBtn) toggleBtn.addEventListener('click', switchCamera);
}

async function requestCameraPermission() {
    try {
        // Check if camera is available
        const devices = await navigator.mediaDevices.enumerateDevices();
        availableCameras = devices.filter(device => device.kind === 'videoinput');
        
        if (availableCameras.length === 0) {
            updateCameraStatus('No cameras found', 'error');
            return;
        }

        updateCameraStatus(`${availableCameras.length} camera(s) detected. Ready to start!`, 'inactive');
        
        // Show toggle button only if multiple cameras
        if (availableCameras.length > 1) {
            document.getElementById('toggleCameraBtn').style.display = 'inline-flex';
        }
        
    } catch (error) {
        console.error('Error checking camera availability:', error);
        updateCameraStatus('Camera access error. Please check permissions.', 'error');
    }
}

async function startCamera() {
    try {
        updateCameraStatus('Starting camera...', 'inactive');
        
        const constraints = {
            video: {
                deviceId: availableCameras[currentCameraIndex]?.deviceId,
                width: { ideal: 1280 },
                height: { ideal: 720 },
                facingMode: 'user'
            },
            audio: false // We're using separate audio recording
        };

        currentStream = await navigator.mediaDevices.getUserMedia(constraints);
        
        const videoElement = document.getElementById('videoPreview');
        const placeholder = document.getElementById('videoPlaceholder');
        
        videoElement.srcObject = currentStream;
        videoElement.style.display = 'block';
        placeholder.style.display = 'none';
        
        // Update UI
        document.getElementById('startCameraBtn').style.display = 'none';
        document.getElementById('stopCameraBtn').style.display = 'inline-flex';
        if (availableCameras.length > 1) {
            document.getElementById('toggleCameraBtn').style.display = 'inline-flex';
        }
        
        updateCameraStatus('Camera is active - Ready for interview practice!', 'active');
        showToast('📹 Camera started successfully!', 'success');
        
        // Start recording timer
        startRecordingTimer();
        
    } catch (error) {
        console.error('Error starting camera:', error);
        let errorMessage = 'Failed to start camera: ';
        
        switch(error.name) {
            case 'NotAllowedError':
                errorMessage += 'Camera access denied. Please allow camera access and try again.';
                break;
            case 'NotFoundError':
                errorMessage += 'No camera found. Please connect a camera and try again.';
                break;
            case 'NotReadableError':
                errorMessage += 'Camera is being used by another application.';
                break;
            default:
                errorMessage += error.message;
        }
        
        updateCameraStatus(errorMessage, 'error');
        showToast(errorMessage, 'danger');
    }
}

function stopCamera() {
    if (currentStream) {
        currentStream.getTracks().forEach(track => track.stop());
        currentStream = null;
    }
    
    const videoElement = document.getElementById('videoPreview');
    const placeholder = document.getElementById('videoPlaceholder');
    
    videoElement.style.display = 'none';
    placeholder.style.display = 'flex';
    
    // Update UI
    document.getElementById('startCameraBtn').style.display = 'inline-flex';
    document.getElementById('stopCameraBtn').style.display = 'none';
    document.getElementById('toggleCameraBtn').style.display = 'none';
    
    updateCameraStatus('Camera stopped. Click "Start Camera" to resume.', 'inactive');
    showToast('📹 Camera stopped', 'info');
    
    // Stop recording timer
    stopRecordingTimer();
}

async function switchCamera() {
    if (availableCameras.length <= 1) return;
    
    currentCameraIndex = (currentCameraIndex + 1) % availableCameras.length;
    
    // Stop current stream
    if (currentStream) {
        currentStream.getTracks().forEach(track => track.stop());
    }
    
    // Start with new camera
    await startCamera();
    showToast(`📹 Switched to camera ${currentCameraIndex + 1}`, 'info');
}

function updateCameraStatus(message, type) {
    const statusElement = document.getElementById('cameraStatus');
    if (statusElement) {
        statusElement.textContent = message;
        statusElement.className = `camera-status ${type}`;
        
        // Add appropriate icon
        const icon = type === 'active' ? 'bi-camera-video-fill' : 
                    type === 'error' ? 'bi-exclamation-triangle-fill' : 
                    'bi-info-circle';
        statusElement.innerHTML = `<i class="bi ${icon}"></i> ${message}`;
    }
}

function startRecordingTimer() {
    recordingStartTime = Date.now();
    const timerElement = document.getElementById('recordingTimer');
    const timerText = document.getElementById('timerText');
    
    if (timerElement && timerText) {
        timerElement.classList.add('active');
        
        timerInterval = setInterval(() => {
            const elapsed = Date.now() - recordingStartTime;
            const minutes = Math.floor(elapsed / 60000);
            const seconds = Math.floor((elapsed % 60000) / 1000);
            timerText.textContent = `${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
        }, 1000);
    }
}

function stopRecordingTimer() {
    if (timerInterval) {
        clearInterval(timerInterval);
        timerInterval = null;
    }
    
    const timerElement = document.getElementById('recordingTimer');
    if (timerElement) {
        timerElement.classList.remove('active');
    }
    
    recordingStartTime = null;
}

// Auto-start camera when questions are generated (optional)
function autoStartCameraOnQuestions() {
    const questionsSection = document.getElementById('questions-list');
    if (questionsSection && questionsSection.children.length > 0) {
        // Automatically request camera permission when questions are loaded
        setTimeout(() => {
            if (!currentStream) {
                showToast('💡 Tip: Start your camera for a more realistic interview experience!', 'info');
            }
        }, 2000);
    }
}

// Call auto-start function when questions are present
document.addEventListener('DOMContentLoaded', () => {
    setTimeout(autoStartCameraOnQuestions, 1000);
});

// Cleanup camera when page unloads
window.addEventListener('beforeunload', () => {
    if (currentStream) {
        currentStream.getTracks().forEach(track => track.stop());
    }
});