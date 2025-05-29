document.getElementById("loginForm").onsubmit = async function(event) {
    event.preventDefault();

    const form = event.target;
    const formData = new FormData(form);
    
    const response = await fetch("/login", {
        method: "POST",
        body: formData,
    });

    const data = await response.json();

    if (response.ok && data.jwt) {
        // Store JWT securely (not shown to user)
        localStorage.setItem("jwt", data.jwt);
        localStorage.setItem("username", document.getElementById("username").value)
        
        window.location.href = data.redirect;

    } else {
        alert(data.message || "Login failed");
    }

    // response = fetch("/upload", {
    //     method: "GET",
    //     headers: {
    //         "Authorization": `Bearer ${localStorage.getItem("jwt")}`,
    //     },
    // });
};