import sqlite3

class DbHandler:
	def __init__(self, sqlite3_file):
		self.conn = sqlite3.connect(sqlite3_file, check_same_thread=False)
		self.cur = self.conn.cursor()

	def createTables(self):
		self.cur.execute("""CREATE TABLE IF NOT EXISTS services (
					name TEXT NOT NULL UNIQUE,
					public_key BLOB NOT NULL UNIQUE
				)""")
		self.cur.execute("""CREATE TABLE IF NOT EXISTS accounts(
					username TEXT NOT NULL,
					service TEXT NOT NULL,
					secret_key BLOB NOT NULL UNIQUE,
					public_key BLOB NOT NULL UNIQUE
				)""")
		self.conn.commit()

	def getServicesNames(self):
		self.cur.execute("SELECT name FROM services")
		return [service[0] for service in self.cur.fetchall()]

	def getAccountsUsernamesForService(self, serviceName):
		self.cur.execute("SELECT username FROM accounts WHERE service=?", (serviceName,))
		return [username[0] for username in  self.cur.fetchall()]

	def insertService(self, name, public_key):
		self.cur.execute("INSERT INTO services (name, public_key) VALUES (?, ?)", (name, public_key))
		self.conn.commit()

	def deleteService(self, name):
		"""Should only be used if service has no accounts left,
		otherwise use \"deleteServiceAndAssociatedAccounts\""""
		self.cur.execute("DELETE FROM services WHERE name=?", (name,))
		self.conn.commit()

	def deleteServiceAndAssociatedAccounts(self, name):
		self.cur.execute("DELETE FROM accounts WHERE service=?", (name,))
		self.cur.execute("DELETE FROM services WHERE name=?", (name,))
		self.conn.commit()

	def insertAccount(self, username, serviceName, secret_key, public_key):
		self.cur.execute("INSERT INTO accounts (username, service, secret_key, public_key) VALUES (?, ?, ?, ?)",
				    (username, serviceName, secret_key, public_key))
		self.conn.commit()

	def deleteAccount(self, username, service):
		self.cur.execute("DELETE FROM accounts WHERE username=? AND service=?", (username, service))
		self.conn.commit()

	def getServicePublicKey(self, name):
		self.cur.execute("SELECT public_key FROM services WHERE name=?", (name,))
		retVal = self.cur.fetchone()
		if not retVal: return None
		return retVal[0]

	def getAccountSecretKey(self, username, service):
		self.cur.execute("SELECT secret_key FROM accounts WHERE username=? AND service=?", (username, service))
		retVal = self.cur.fetchone()
		if not retVal: return None
		return retVal[0]

	def getAccountPublicKey(self, username, service):
		self.cur.execute("SELECT public_key FROM accounts WHERE username=? AND service=?", (username, service))
		retVal = self.cur.fetchone()
		if not retVal: return None
		return retVal[0]

	def closeDb(self):
		self.conn.close()
		print("Conneciton to SQLite3 database is closed.")

# MAIN (TESTING ONLY)
if __name__ == "__main__":
	print("DbHandler main is being run")
	db = DbHandler("data.sqlite3")
	print(f"{db.getServicesNames()=}")
	db.closeDb()
