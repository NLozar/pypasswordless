# PyPasswordless

### THIS IS A TECH DEMO. DO NOT USE IN PRODUCTION!
* **Many critical standard security practices have deliberately been forgone.**

## Purpose
Goal is to demonstrate a technological feasibility of:
* Enabling user registration and login using public key infrastructure (PKI) rather than relying on traditional usernames and passwords
* Eliminating the need for shared secrets between the user and service for purposes of two-factor authentication (2FA) such as with authenticator codes (RFC 6238)

## How to run
### Redis
Unfortunately, Flask doesn't have great built-in support for real-time features such as JavaScript's `EventSource`, so to make this demo's real-time functionality work, it requires a Redis server running on port `6379` (by default).  

Probably the easiest way to do this is using Docker. If you have Docker installed, run command:

	docker run --name pypasswordless-redis -p 6379:6379 -d redis:alpine

### Running the client and server
Once Redis server is up, client API can be started by executing `python app.py` (Windows) or `python3 app.py` (Linux) in "client" folder. Client should be available on <https://localhost:8000>.

Note that *ad hoc* self-signed nature of the TLS certificates will result in browser raising the invalid certificate authority error for both client and server.

Similarly, server can be run by executing `python api.py` (Windows) or `python3 api.py` (Linux) in "server" folder. Server should be available on <https://localhost:5000>.

## Basic usage
Note if words *"client"* or *"server"* appear in *italic font* in this document, this signifies that they refer to specific *server* and *client* components of this particular demo.

### Server
*Server* is meant to simulate servers of services to which user may be registered to. It allows basic creation and deletion of simulated services as well as deletion of individual accounts of a particular simulated service.

### Client
*Client* represents an authenticator app with which user authenticate themselves to log in (or register to) a particular service. It also allows for deletion of accounts.

**Note that deleting an account or service on either *server* or *client* does NOT delete it on the other.**

### Simulating a login or registration
Going to any 'service' page (the one with the service's login/registration token) in the *server* can be thought of as going to a login/registration page of some arbitrary web service. To log in or register to said service, user shall copy the presented token and paste it into the token receptacle text area in the *client* and click "Process token" button. **The *client* has to be opened in a separate tab. Leaving *server's* service page will terminate the session, rendering token invalid.**

On subsequent page, user will have an option to either register a new account to that service or if they already have existing accounts for it, they can click on one of them to log in with that particular account.  
Upon doing either of these, user should receive an alert with status of their request.

Similarly, on the *server*, upon successful login an alert indicating such should appear. Upon successful registration of a new account, said account name should automatically appear under "Registered users."

## Known issues
* Running the *server* with Flask's built-in `app.run(...)` debugger (which is what is described in *"How to run"*) will lead to session entries not being correctly flushed (unsubscribed) from Redis cache if browser tab is suddenly closed (if session is terminated any other way [such as navigating elsewhere] other than closing the tab, it should still work).  
This isn't a problem if server API is run using `gunicorn` with `gevent` worker class, however gunicorn doesn't support *ad hoc* TLS and currently login/registration tokens are hardcoded to https.

* Deleting the last account of service X in *client* will cause "No accounts found for service X" error. This is because there's no reason to keep service in *client's* database if there are no accounts associated with it and thus gets deleted, and then when frontend site refreshes it appears to be looking for a service which is no longer in *client's* database.
