from flask import Flask, request, render_template
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
from dbhandler import DbHandler
import base64
import helpers
import json
import requests
import traceback

app = Flask(__name__)
HOST = "127.0.0.1"
PORT = 8000
db = DbHandler("data.sqlite3")
db.createTables()
INTERNAL_SERVER_ERROR = "Internal server error"

@app.route("/", methods=["GET"])
def index():
	try:
		services = getListOfServices()[0]
		print("Services to render:", services)	# DEBUG
		return render_template("index.html", services=services)
	except Exception as err:
		print("Error fetching list of services", err)
		traceback.print_exc()
		return INTERNAL_SERVER_ERROR, 500

@app.route("/getServiceNames", methods=["GET"])
def getListOfServices():
	try:
		listOfServices = db.getServicesNames()
		print("List of services:", listOfServices)	# DEBUG
		return listOfServices, 200
	except Exception as err:
		print("Error when listing services' names:", err)
		traceback.print_exc()
		return INTERNAL_SERVER_ERROR, 500

@app.route("/service", methods=["GET"])
def service():
	try:
		serviceName = request.args.get("service-name")
		if not serviceName:
			return "Missing service name", 400
		accounts = db.getAccountsUsernamesForService(serviceName)
		if not accounts:
			return f"No accounts found for service \"{serviceName}\""
		return render_template("serviceAccounts.html", accounts=accounts, serviceName=serviceName)
	except Exception as err:
		print(f"Error getting service accounts: {err}")
		traceback.print_exc()
		return INTERNAL_SERVER_ERROR, 500

@app.route("/deleteService", methods=["DELETE"])
def deleteService():
	try:
		service = request.args.get("service")
		if not service:
			return "Missing service name", 400
		db.deleteServiceAndAssociatedAccounts(service)
		return f"Deleted \"{service}\" and associated accounts.", 204
	except Exception as err:
		print(f"Error deleting service: {err}")
		traceback.print_exc()
		return INTERNAL_SERVER_ERROR, 500

@app.route("/processToken", methods=["GET"])
def processToken():
	try:
		token = request.args.get("token")
		if not token: raise KeyError
		payload = helpers.verifyAndParseToken(token)
		serviceName = payload["serviceName"]
		accounts = db.getAccountsUsernamesForService(serviceName)
		return render_template(
				"tokenServiceAccounts.html",
				serviceName=serviceName,
				accounts=accounts,
				loginUrl=payload["userLoginAPIEndpoint"],
				registrationUrl=payload["userRegistrationAPIEndpoint"]
			)
	except KeyError:
		print("Malformed request\nrequest.form:", request.form)
		return "Malformed request", 400
	except InvalidSignature:
		return "Invalid payload signature", 403
	except Exception as err:
		print("Error when processing token:", err)
		traceback.print_exc()
		return INTERNAL_SERVER_ERROR, 500

@app.route("/login", methods=["POST"])
def login():
	try:
		token_str = request.form.get("token")
		username = request.form.get("username")
		if not token_str or not username: raise KeyError
		payload = helpers.verifyAndParseToken(str(token_str))
		serviceName = payload["serviceName"]
		services = getListOfServices()[0]
		servicePublicKey = Ed25519PublicKey.from_public_bytes(base64.b64decode(payload["publicKey"].encode("utf-8")))
		if serviceName in services:
			servicePublicKeyDb = db.getServicePublicKey(serviceName)
			if servicePublicKey.public_bytes_raw() != servicePublicKeyDb:
				print(f"Service \"{serviceName}\" public key mismatched against stored.")
				return "Service public key mismatch", 401
		userSecretKey = db.getAccountSecretKey(username, serviceName)
		if not userSecretKey:
			print(f"User \"{username}\" secret key not found. Requested for service \"{serviceName}\"")	# DEBUG
			return f"User \"{username}\" secret key not found", 404
		userSecretKey = Ed25519PrivateKey.from_private_bytes(userSecretKey)
		userPublicKey = db.getAccountPublicKey(username, serviceName)
		if not userPublicKey:
			print(f"User \"{username}\" public key not found. Requested for service \"{serviceName}\"")	# DEBUG
			return f"User \"{username}\" public key not found", 404
		loginPayload = json.dumps({
			"username": username,
			"serviceName": serviceName,
			"userPublicKey": base64.b64encode(userPublicKey).decode("utf-8"),
			"sessionId": payload["sessionId"]
		})
		sig = userSecretKey.sign(loginPayload.encode())
		data = {
			"payload": loginPayload,
			"sessionId": payload["sessionId"],
			"signature": base64.b64encode(sig).decode("utf-8")
		}
		resp = requests.post(payload["userLoginAPIEndpoint"], data=data, verify=False)
		return resp.text, resp.status_code
	except KeyError:
		print("Malformed request\nrequest.form:", request.form)
		return "Malformed request", 400
	except InvalidSignature:
		return "Invalid payload signature", 401
	except Exception as err:
		print(f"Logging user in failed: {err}")
		traceback.print_exc()
		return INTERNAL_SERVER_ERROR, 500

@app.route("/register", methods=["POST"])
def register():
	try:
		token_str = request.form.get("token")
		username = request.form.get("username")
		if not token_str or not username: raise KeyError
		payload = helpers.verifyAndParseToken(str(token_str))
		serviceName = payload["serviceName"]
		services = getListOfServices()[0]
		servicePublicKey = Ed25519PublicKey.from_public_bytes(base64.b64decode(payload["publicKey"].encode("utf-8")))
		newService = False
		if serviceName in services:
			servicePublicKeyDb = db.getServicePublicKey(serviceName)
			if servicePublicKey.public_bytes_raw() != servicePublicKeyDb:
				return "Service public key mismatch", 401
		else:
			newService = True
		userSecretKey = Ed25519PrivateKey.generate()
		userPublicKey = userSecretKey.public_key().public_bytes_raw()
		# send registration request to service before inserting account into db
		# in case something fails on service end
		registrationPayload = json.dumps({
			"username": username,
			"serviceName": serviceName,
			"userPublicKey": base64.b64encode(userPublicKey).decode("utf-8"),
			"sessionId": payload["sessionId"]
		})
		sig = userSecretKey.sign(registrationPayload.encode())
		data = {
			"payload": registrationPayload,
			"sessionId": payload["sessionId"],
			"signature": base64.b64encode(sig).decode("utf-8")
		}
		resp = requests.post(payload["userRegistrationAPIEndpoint"], data=data, verify=False)
		print(f"Response to registration attempt: {resp.status_code}: {resp.text}")	# DEBUG
		if resp.status_code == 200:
			db.insertAccount(username, serviceName, userSecretKey.private_bytes_raw(), userPublicKey)
			if newService:
				db.insertService(serviceName, servicePublicKey.public_bytes_raw())
		return resp.text, resp.status_code
	except KeyError:
		print("Malformed request\nrequest.form:", request.form)
		return "Malformed request", 400
	except InvalidSignature:
		return "Invalid payload signature", 401
	except Exception as err:
		print("Error when registering new account:", err)
		traceback.print_exc()
		return INTERNAL_SERVER_ERROR, 500

@app.route("/deleteAccount", methods=["DELETE"])
def deleteAccount():
	try:
		account = request.args.get("account")
		service = request.args.get("service")
		if not account or not service:
			return "Missing account name or service name or both.", 400
		db.deleteAccount(account, service)
		if not db.getAccountsUsernamesForService(service):
			db.deleteService(service)
		return f"Deleted account \"{account}\" for service \"${service}\".", 204
	except Exception as err:
		print(f"Error deleting service: {err}")
		traceback.print_exc()
		return INTERNAL_SERVER_ERROR, 500

if __name__ == "__main__":
	print("Server is starting...")
	app.run(host=HOST, port=PORT, debug=True, ssl_context="adhoc")
	db.closeDb()
