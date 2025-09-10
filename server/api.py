from flask import Flask, request, Response, render_template
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.exceptions import InvalidSignature
from dbhandler import DbHandler
import json
import base64
import uuid
from redis import Redis
import helpers
import atexit
import traceback

app = Flask(__name__)
HOST = "127.0.0.1"
FLASK_PORT = 5000
REDIS_PORT = 6379
db = DbHandler("data.sqlite3")
db.createTables()
r = Redis(host=HOST, port=REDIS_PORT, decode_responses=True)
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
		listOfServices = db.getServiceNames()
		print("List of services:", listOfServices)	# DEBUG
		return listOfServices, 200
	except Exception as err:
		print("Error when listing services' names:", err)
		traceback.print_exc()
		return INTERNAL_SERVER_ERROR, 500

@app.route("/createService", methods=["POST"])
def createService():
	try:
		serviceName = request.form["service name"]
	except KeyError:
		print("Malformed request\nrequest.form:", request.form)
		return "Malformed request", 400
	except Exception as err:
		print("Error when processing request to createService:", err)
		traceback.print_exc()
		return INTERNAL_SERVER_ERROR, 500
	try:
		listOfServices, status = getListOfServices()
		if status >= 400:
			raise Exception
		if (serviceName in listOfServices):
			return f"Service name \"{serviceName}\" already taken", 409
	except Exception as err:
		print("Error creating service 1:", err)
		traceback.print_exc()
		return INTERNAL_SERVER_ERROR, 500
	try:
		secret_key = Ed25519PrivateKey.generate()
		db.insertService(serviceName, secret_key.private_bytes_raw(), secret_key.public_key().public_bytes_raw())
		return "Service created", 200
	except Exception as err:
		print("Error creating service 2:", err)
		traceback.print_exc()
		return INTERNAL_SERVER_ERROR, 500

@app.route("/service", methods=["GET"])
def service():
	try:
		serviceName = request.args.get("service-name")
		print("Details for service:", serviceName)	# DEBUG
		if not serviceName:
			print("Bad request for service details. request params:", request.args.to_dict())
			return "Missing service-name parameter", 400
		secret_key_bytes = db.getServiceSecretKey(serviceName)
		public_key = db.getServicePublicKey(serviceName)
		if not public_key or not secret_key_bytes:
			return f"Service named \"{serviceName}\" not found.", 404
		sessionId = str(uuid.uuid4())
		payload = json.dumps({
			"serviceName": serviceName,
			"publicKey": base64.b64encode(public_key).decode("utf-8"),
			"sessionId": sessionId,
			"userRegistrationAPIEndpoint": f"https://{HOST}:{FLASK_PORT}/registerUser",
			"userLoginAPIEndpoint": f"https://{HOST}:{FLASK_PORT}/authenticateUser"
		})
		secret_key = Ed25519PrivateKey.from_private_bytes(secret_key_bytes)
		sig = secret_key.sign(payload.encode())
		token = json.dumps({
			"payload": payload,
			"signature": base64.b64encode(sig).decode("utf-8")
		})
		accounts = db.getUsersOfService(serviceName)
		return render_template("service.html", serviceName=serviceName, token=token, sessionId=sessionId, accounts=accounts)
	except Exception as err:
		print(f"Error getting service details. {request.args.to_dict()=}\nError: {err}")
		traceback.print_exc()
		return INTERNAL_SERVER_ERROR, 500

SHUTDOWN_MESSAGE = "__CLOSE__"

def sessionStreamHandling(sessionId):
	pubsub = r.pubsub()
	try:
		pubsub.subscribe(sessionId)
		print(f"Subscribed {sessionId}")	# DEBUG
		yield f"event: channel-event\ndata: Subscribed {sessionId}\n\n"
		for message in pubsub.listen():
			if message["type"] == "message":
				if message["data"] == SHUTDOWN_MESSAGE:
					print(f"Shutting down channel: {sessionId}")	# DEBUG
					break
				yield f"data: {message['data']}\n\n"
	finally:
		pubsub.unsubscribe(sessionId)
		r.delete(sessionId)
		print(f"Session {sessionId} terminated")

@app.route("/listenForLogin")
def listenForLogin():
	sessionId = request.args.get("sessionId")
	if not sessionId:
		return "Mission sessionId", 400
	r.set(sessionId, json.dumps({"status": "pending"}))
	return Response(sessionStreamHandling(sessionId), mimetype="text/event-stream")

@app.route("/unsubscribe", methods=["POST"])
def unsubscribe():
	try:
		channel = request.form.get("channel")
		print(f"Received unsubscribe for {channel}")	# DEBUG
		r.publish(str(channel), SHUTDOWN_MESSAGE)
	except Exception as err:
		print(f"/unsubscribe endpoint crapped out, whatever: {err}")	# DEBUG
		traceback.print_exc()
		return INTERNAL_SERVER_ERROR, 500
	return "OK", 200

@app.route("/registerUser", methods=["POST"])
def registerUser():
	try:
		print(f"{request.form.to_dict()=}")	# DEBUG
		sessionId = request.form.get("sessionId")
		if not sessionId: return "Malformed request. Missing sessionId.", 400
		if not r.get(str(sessionId)):
			# If session has since been closed, there's no point in wasting resources with crypto ops
			# since there's no page to log user in to
			return "Session expired (or never existed)", 410
		payload = helpers.verifyAndParseReqData(str(request.form.get("payload")), str(request.form.get("signature")))
		if sessionId != payload["sessionId"]:
			# making sure sessionId hasn't been swapped by MitM
			return f"sessionId \"{sessionId}\" doesn't match the signed one in the payload: \"{payload['sessionId']}\"", 401
		print(f"{payload=}")	# DEBUG
		services = getListOfServices()[0]
		if payload["serviceName"] not in services:
			return "Service not found", 404
		usersOfService = db.getUsersOfService(payload["serviceName"])
		if payload["username"] in usersOfService:
			return f"Username \"{payload['username']}\" taken.", 409
		db.insertNewUser(payload["username"], payload["serviceName"], base64.b64decode(payload["userPublicKey"].encode("utf-8")))
		event = json.dumps({
			"eventType": "registration",
			"username": payload["username"]
		})
		r.publish(sessionId, event)
		return f"Registered user \"{payload['username']}\".", 200
	except InvalidSignature:
		return "Invalid payload signature", 401
	except Exception as err:
		print(f"Registring user failed: {err}")
		traceback.print_exc()
		return INTERNAL_SERVER_ERROR, 500

@app.route("/authenticateUser", methods=["POST"])
def authenticateUser():
	try:
		print(f"{request.form.to_dict()=}")	# DEBUG
		sessionId = request.form.get("sessionId")
		if not sessionId: return "Malformed request. Missing sessionId.", 400
		if not r.get(str(sessionId)):
			# If session has since been closed, there's no point in wasting resources with crypto ops
			# since there's no page to log user in to
			return "Session expired (or never existed)", 410
		payload = helpers.verifyAndParseReqData(str(request.form.get("payload")), str(request.form.get("signature")))
		if sessionId != payload["sessionId"]:
			# making sure sessionId hasn't been swapped by MitM
			return f"sessionId \"{sessionId}\" doesn't match the signed one in the payload: \"{payload['sessionId']}\"", 401
		print(f"{payload=}")	# DEBUG
		services = getListOfServices()[0]
		if payload["serviceName"] not in services:
			return "Service not found", 404
		usersOfService = db.getUsersOfService(payload["serviceName"])
		if payload["username"] not in usersOfService:
			return f"Username \"{payload['username']}\" not found.", 404
		userPublicKeyDb = db.getUserPublicKey(payload["username"], payload["serviceName"])
		if userPublicKeyDb != base64.b64decode(payload["userPublicKey"].encode("utf-8")):
			return "User public key mismatch.", 401
		event = json.dumps({
			"eventType": "login",
			"username": payload["username"]
		})
		r.publish(sessionId, event)
		return f"Logged in user \"{payload['username']}\".", 200
	except InvalidSignature:
		return "Invalid payload signature", 401
	except Exception as err:
		print(f"Logging user in failed: {err}")
		traceback.print_exc()
		return INTERNAL_SERVER_ERROR, 500

@app.route("/deleteService", methods=["DELETE"])
def deleteService():
	try:
		serviceName = request.args.get("service-name")
		print("Service name to delete:", serviceName)	# DEBUG
		if not serviceName:
			print("Bad request for deleting service. request params:", request.args.to_dict())
			return "Missing service-name parameter", 400
	except Exception as err:
		print("Error deleting service 1:", err)
		traceback.print_exc()
		return INTERNAL_SERVER_ERROR, 500
	try:
		listOfServices, status = getListOfServices()
		if status >= 400:
			raise Exception
		if serviceName not in listOfServices:
			return f"Service name \"{serviceName}\" not found", 404
		db.deleteServiceAndItsUsersAccounts(serviceName)
		return "Service and its users deleted", 200
	except Exception as err:
		print("Error deleting service 2:", err)
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
		return f"Deleted account \"{account}\" for service \"{service}\".", 204
	except Exception as err:
		print(f"Error deleting service: {err}")
		traceback.print_exc()
		return INTERNAL_SERVER_ERROR, 500

def cleanup():
	try:
		db.closeDb()
		r.flushall()
		print("Database connection closed and cache wiped.")
	except Exception as err:
		print(f"Error cleaning up: {err}")
		traceback.print_exc()

if __name__ == "__main__":
	atexit.register(cleanup)
	print("Server is starting...")
	app.run(host=HOST, port=FLASK_PORT, debug=True, ssl_context="adhoc")
