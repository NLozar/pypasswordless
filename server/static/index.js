async function createNewService() {
	const url = `/createService`;
	const serviceName = document.getElementById("service-name").value;
	try {
		const resp = await fetch(url, {
			method: "POST",
			headers: {
				"Content-Type": "application/x-www-form-urlencoded"
			},
			body: new URLSearchParams({ "service name": serviceName })
		});
		if (resp.status >= 400) {
			alert(`${resp.status}: ${await resp.text()}`);
			return;
		}
		location.reload();
	}
	catch (err) {
		console.error(`Creating service failed:\n${err}`);
	}
}

async function listServices() {
	console.log("listServices triggered");
	const url = `/getServiceNames`;
	try {
		const resp = await fetch(url);
		const listOfServices = await resp.json();
		console.log(listOfServices);
		for (const service of listOfServices) {
			console.log(service);
		}
	}
	catch (err) {
		console.error(`Listing services failed:\n${err}`);
	}
}

async function deleteService(serviceName) {
	if (!confirm("This will also delete all users' accounts of that service. Proceed?")) return;
	const url = `/deleteService?service-name=${serviceName}`;
	try {
		const resp = await fetch(url, { method: "DELETE" });
		if (resp.status >= 400) {
			alert(`${resp.status}: ${await resp.text()}`);
			return;
		}
		location.reload();
	}
	catch (err) {
		console.error(`Error deleting service:\n${err}`);
	}
}

function copyKeyToClipboard() {
	const field = document.getElementById("key-field").value;
	navigator.clipboard.writeText(field);
	console.log(`Copied: ${field}`);
}

function listenForLogin(sessionId) {
	const url = `listenForLogin?sessionId=${sessionId}`;
	const es = new EventSource(url);
	console.log("Listening for login");
	es.onmessage = event => {
		console.log(`Event data: ${event.data}`);
		data = JSON.parse(event.data)
		if (data.eventType == "login") alert(`User \"${data.username}\" logged in.`);
		else if (data.eventType == "registration") location.reload();
	}
	es.onerror = err => {
		console.error(`EventSource failure: ${err}`);
	}
	window.addEventListener("beforeunload", () => {
		const formData = new FormData();
		formData.append("channel", sessionId);
		navigator.sendBeacon("/unsubscribe", formData);
	});
}

async function deleteAccount(account, service) {
	if (!confirm(`User \"${account} will no longer be able to log into service \"${service}\"."`)) return;
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
