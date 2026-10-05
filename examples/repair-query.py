def lookup(db, name):
    return db.execute("SELECT name FROM users WHERE name = '" + name + "'").fetchall()
