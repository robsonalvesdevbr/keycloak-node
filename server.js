const session = require("express-session");
const Keycloak = require("keycloak-connect");
const express = require("express");
const app = express();

const memoryStore = new session.MemoryStore();

app.use(
	session({
		secret: "mySecret",
		resave: false,
		saveUninitialized: true,
		store: memoryStore,
	}),
);

const keycloak = new Keycloak({
	store: memoryStore,
	scope: "myclient_access_scope",
});

app.use(keycloak.middleware());

app.get("/complain", keycloak.protect(), (req, res) => {
	// This route is protected by Keycloak
	res.send("This is a protected route");
});

app.get("/user", keycloak.protect("realm:user"), (req, res) => {
	// This route is protected by Keycloak
	res.send("This is a protected route user");
});

app.get("/administrator", keycloak.protect("realm:admin"), (req, res) => {
	// This route is protected by Keycloak
	res.send("This is a protected route user");
});

app.get("/protected", keycloak.protect(), (req, res) => {
	const tokenContent = req.kauth.grant.access_token.content;
	const scope = tokenContent.scope;

	console.log("Escopos do Token:", scope);
	res.json({ message: "Rota protegida!", scopes: scope.split(" ") });
});

app.use(keycloak.middleware({ logout: "/logoff" }));
app.use(keycloak.middleware({ admin: "/callbacks" }));

app.listen(3000, () => {
	console.log("App listening on port 3000");
});
