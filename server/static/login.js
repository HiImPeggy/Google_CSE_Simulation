document.getElementById("loginForm").onsubmit = async function(event) {
    event.preventDefault();
    const form = event.target;
    const formData = new FormData(form);
    try {
        const response = await fetch("/login", {
            method: "POST",
            body: formData,
        });
        const data = await response.json();
        console.log("Response from server:", data); // Debug: Check response
        if (response.ok && data.status === "success") {
            localStorage.setItem("jwt", data.jwt);
            localStorage.setItem("username", document.getElementById("username").value);
            window.location.href = data.redirect;
        } else if (response.ok && data.status === "qrcode") {
            const qrcodeDiv = document.getElementById("qrcode");
            if (!qrcodeDiv) {
                console.error("qrcode div not found!");
                return;
            }
            qrcodeDiv.innerHTML = `
                <p>Please scan the following QR Code with Google Authenticator to set up 2FA:</p>
                <img src="data:image/png;base64,${data.qrcode}" alt="QR Code">
                <p>After scanning, please re-enter your username, password, and the OTP from Google Authenticator.</p>
            `;
            document.getElementById("otp").value = "";
            document.getElementById("otp").focus(); // Focus on OTP field
            setTimeout(() => {
                window.location.reload();
            }, 60000); // Reload page
        } else {
            alert(data.message || "Login failed");
        }
    } catch (error) {
        console.error("Error during fetch:", error);
    }
};