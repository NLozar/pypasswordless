import sqlite3

class DbHandler:
	def __init__(self, sqlite3_file):
		self.conn = sqlite3.connect(sqlite3_file, check_same_thread=False)
		self.cur = self.conn.cursor()

	def createTables(self):
		self.cur.execute("""CREATE TABLE IF NOT EXISTS services (
					name TEXT NOT NULL UNIQUE,
					secret_key BLOB NOT NULL UNIQUE,
					public_key BLOB NOT NULL UNIQUE
				)""")
		self.cur.execute("""CREATE TABLE IF NOT EXISTS users(
					username TEXT NOT NULL,
					service TEXT NOT NULL,
					public_key BLOB NOT NULL UNIQUE
				)""")
		self.conn.commit()

	def getServiceNames(self):
			self.cur.execute("SELECT name FROM services")
			return [service[0] for service in self.cur.fetchall()]

	def insertService(self, name, secret_key, public_key):
		self.cur.execute("INSERT INTO services (name, secret_key, public_key) VALUES (?, ?, ?)", (name, secret_key, public_key))
		self.conn.commit()

	def deleteServiceAndItsUsersAccounts(self, name):
		self.cur.execute("DELETE FROM services WHERE name=?", (name,))
		self.cur.execute("DELETE FROM users WHERE service=?", (name,))
		self.conn.commit()

	def getServicePublicKey(self, name):
		self.cur.execute("SELECT public_key FROM services WHERE name=?", (name,))
		retVal = self.cur.fetchone()
		if not retVal: return None
		return retVal[0]

	def getServiceSecretKey(self, name):
		self.cur.execute("SELECT secret_key FROM services WHERE name=?", (name,))
		retVal = self.cur.fetchone()
		if not retVal: return None
		return retVal[0]

	def getUsersOfService(self, service):
		self.cur.execute("SELECT username FROM users WHERE service=?", (service,))
		return [user[0] for user in self.cur.fetchall()]

	def insertNewUser(self, username, service, public_key):
		self.cur.execute("INSERT INTO users (username, service, public_key) VALUES (?, ?, ?)", (username, service, public_key))
		self.conn.commit()

	def getUserPublicKey(self, username, service):
		self.cur.execute("SELECT public_key FROM users WHERE username=? AND service=?", (username, service))
		retVal = self.cur.fetchone()
		if not retVal: return None
		return retVal[0]

	def deleteAccount(self, username, service):
		self.cur.execute("DELETE FROM users WHERE username=? AND service=?", (username, service))
		self.conn.commit()

	def closeDb(self):
		self.conn.close()
		print("Conneciton to SQLite3 database is closed.")

# MAIN (TESTING ONLY)
if __name__ == "__main__":
	print("DbHandler main is being run")
	db = DbHandler("data.sqlite3")
	db.closeDb()
