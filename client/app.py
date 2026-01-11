from flask import Flask, request, render_template
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
from dbhandler import DbHandler
import base64
import helpers
import json
import requests
import logging

app = Flask(__name__)
HOST = "127.0.0.1"
PORT = 8000
db = DbHandler("data.sqlite3")
db.createTables()
INTERNAL_SERVER_ERROR = "Internal server error"
logger = logging.getLogger(__name__)
log_handler = logging.StreamHandler()
log_formatter = logging.Formatter("%(req_ip)s - - %(asctime)s.%(msecs)s - %(levelname)s - [func: %(funcName)s]: %(message)s", datefmt="%H:%M:%S", defaults={"req_ip": "N/A"})
log_handler.setFormatter(log_formatter)
logger.addHandler(log_handler)
logger.setLevel(logging.DEBUG)

@app.route("/", methods=["GET"])
def index():
	try:
		services = getListOfServices()[0]
		logger.debug("Services to render: %s", services, extra={"req_ip": request.remote_addr})
		return render_template("index.html", services=services)
	except Exception as err:
		logger.exception("Error fetching list of services: %s", err, extra={"req_ip": request.remote_addr})
		return INTERNAL_SERVER_ERROR, 500

@app.route("/getServiceNames", methods=["GET"])
def getListOfServices():
	try:
		listOfServices = db.getServicesNames()
		logger.debug("List of services: %s", listOfServices, extra={"req_ip": request.remote_addr})
		return listOfServices, 200
	except Exception as err:
		logger.exception("Error when listing services' names: %s", err, extra={"req_ip": request.remote_addr})
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
		logger.exception("Error getting service accounts: %s", err, extra={"req_ip": request.remote_addr})
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
		logger.exception("Error deleting service: %s", err, extra={"req_ip": request.remote_addr})
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
		logger.warning("Malformed request. request.form: %s", request.form, extra={"req_ip": request.remote_addr})
		return "Malformed request", 400
	except InvalidSignature:
		return "Invalid payload signature", 403
	except Exception as err:
		logger.exception("Error when processing token: %s", err, extra={"req_ip": request.remote_addr})
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
		servicePublicKey = Ed25519PublicKey.from_public_bytes(base64.urlsafe_b64decode(payload["publicKey"].encode("utf-8")))
		if serviceName in services:
			servicePublicKeyDb = db.getServicePublicKey(serviceName)
			if servicePublicKey.public_bytes_raw() != servicePublicKeyDb:
				logger.warning("Service \"%s\" public key mismatched against stored.", serviceName, extra={"req_ip": request.remote_addr})
				return "Service public key mismatch", 401
		userSecretKey = db.getAccountSecretKey(username, serviceName)
		if not userSecretKey:
			logger.debug("User \"%s\" secret key not found. Requested for service \"%s\"", username, serviceName, extra={"req_ip": request.remote_addr})
			return f"User \"{username}\" secret key not found", 404
		userSecretKey = Ed25519PrivateKey.from_private_bytes(userSecretKey)
		userPublicKey = db.getAccountPublicKey(username, serviceName)
		if not userPublicKey:
			logger.debug("User \"%s\" public key not found. Requested for service \"%s\"", username, serviceName, extra={"req_ip": request.remote_addr})
			return f"User \"{username}\" public key not found", 404
		loginPayload = json.dumps({
			"username": username,
			"serviceName": serviceName,
			"userPublicKey": base64.urlsafe_b64encode(userPublicKey).decode("utf-8"),
			"sessionId": payload["sessionId"]
		})
		sig = userSecretKey.sign(loginPayload.encode())
		data = {
			"payload": loginPayload,
			"sessionId": payload["sessionId"],
			"signature": base64.urlsafe_b64encode(sig).decode("utf-8")
		}
		resp = requests.post(payload["userLoginAPIEndpoint"], data=data, verify=False)
		return resp.text, resp.status_code
	except KeyError:
		logger.warning("Malformed request. request.form: %s", request.form, extra={"req_ip": request.remote_addr})
		return "Malformed request", 400
	except InvalidSignature:
		return "Invalid payload signature", 401
	except Exception as err:
		logger.exception("Logging user in failed: %s", err, extra={"req_ip": request.remote_addr})
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
		servicePublicKey = Ed25519PublicKey.from_public_bytes(base64.urlsafe_b64decode(payload["publicKey"].encode("utf-8")))
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
			"userPublicKey": base64.urlsafe_b64encode(userPublicKey).decode("utf-8"),
			"sessionId": payload["sessionId"]
		})
		sig = userSecretKey.sign(registrationPayload.encode())
		data = {
			"payload": registrationPayload,
			"sessionId": payload["sessionId"],
			"signature": base64.urlsafe_b64encode(sig).decode("utf-8")
		}
		resp = requests.post(payload["userRegistrationAPIEndpoint"], data=data, verify=False)
		logger.debug(f"Response to registration attempt: {resp.status_code}: {resp.text}", extra={"req_ip": request.remote_addr})
		if resp.status_code == 200:
			db.insertAccount(username, serviceName, userSecretKey.private_bytes_raw(), userPublicKey)
			if newService:
				db.insertService(serviceName, servicePublicKey.public_bytes_raw())
		return resp.text, resp.status_code
	except KeyError:
		logger.warning("Malformed request. request.form: %s", request.form, extra={"req_ip": request.remote_addr})
		return "Malformed request", 400
	except InvalidSignature:
		return "Invalid payload signature", 401
	except Exception as err:
		logger.exception("Error when registering new account: %s", err, extra={"req_ip": request.remote_addr})
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
		return f"Deleted account \"{account}\" for service \"{service}\".", 204
	except Exception as err:
		logger.exception("Error deleting service: %s", err, extra={"req_ip": request.remote_addr})
		return INTERNAL_SERVER_ERROR, 500

if __name__ == "__main__":
	print("Server is starting...")
	app.run(host=HOST, port=PORT, debug=True, ssl_context="adhoc")
	db.closeDb()
