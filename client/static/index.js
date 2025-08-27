async function processToken() {
	const token = document.getElementById("token-receptacle").value.trim();
	const url = `/processToken?token=${encodeURIComponent(token)}`;
	location.href = url;
}

async function login(accountName) {
	console.log("Login initiated");
	const token = new URL(window.location.href).searchParams.get("token");
	try {
		const resp = await fetch("/login", {
			method: "POST",
			headers: { "Content-Type": "application/x-www-form-urlencoded" },
			body: new URLSearchParams({
				token: token,
				username: accountName
			})
		});
		alert(`${resp.status}: ${await resp.text()}`);
	}
	catch (err) {
		console.error(`Login failed:\n${err}`);
	}
}

async function register() {
	console.log("Registration initiated");
	const token = new URL(window.location.href).searchParams.get("token");
	const username = document.getElementById("username").value;
	if (!username) {
		alert("Enter username");
		return;
	}
	try {
		const resp = await fetch("/register", {
			method: "POST",
			headers: {
				"Content-Type": "application/x-www-form-urlencoded"
			},
			body: new URLSearchParams({
				token: token,
				username: username
			})
		});
		alert(`${resp.status}: ${await resp.text()}`);
	}
	catch (err) {
		console.error(`Account registration failed:\n${err}`);
	}
}

async function deleteService(service) {
	if (!confirm(`This will also delete all accounts associated with \"${service}\" service. Proceed?`)) return;
	const url = `/deleteService?service=${service}`;
	try {
		const resp = await fetch(url, { method: "DELETE" });
		if (resp.status >= 400) {
			alert(`${resp.status}: ${await resp.text()}`);
			return;
		}
		location.reload();
	}
	catch (err) {
		console.error(`Deleting service failed:\n${err}`);
	}
}

async function deleteAccount(account, service) {
	const url = `/deleteAccount?account=${account}&service=${service}`;
	try {
		const resp = await fetch(url, { method: "DELETE" });
		if (resp.status >= 400) {
			alert(`${resp.status}: ${await resp.text()}`);
			return;
		}
		location.reload();
	}
	catch (err) {
		console.error(`Deleting account failed:\n${err}`);
	}
}
