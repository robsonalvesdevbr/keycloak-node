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
	scope: "app-payment-scope",
});

app.use(keycloak.middleware());
app.use(keycloak.middleware({ logout: "/logoff" }));
app.use(keycloak.middleware({ admin: "/callbacks" }));

// Middleware global para verificar role ou scope padrão
defaultScopeMiddleware = (req, res, next) => {
	if (req.path === "/logoff" || req.path === "/callbacks") {
		return next();
	}

	if (req.kauth?.grant?.access_token) {
		const tokenContent = req.kauth.grant.access_token.content;
		const scopes = tokenContent.scope.split(" ");
		const roles = tokenContent.realm_access?.roles || []; //

		// Verifica se o escopo padrão ou a role padrão está presente
		//if (scopes.includes("app-payment-scope") || roles.includes("user")) {
		//	return next();
		//}

		if (scopes.includes("app-payment-scope")) {
			return next();
		}
	}

	res.status(403).send("Forbidden: Insufficient scope or role");
};

// Aplica o middleware global
app.use(defaultScopeMiddleware);

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

app.get("/all", keycloak.protect(["realm:user", "realm:admin"]), (req, res) => {
	// This route is protected by Keycloak
	res.send("This is a protected route user");
});

app.get("/protected", keycloak.protect(), (req, res) => {
	const tokenContent = req.kauth.grant.access_token.content;
	const scope = tokenContent.scope;

	//console.log("Escopos do Token:", scope);
	res.json({ message: "Rota protegida!", scopes: scope.split(" ") });
});

app.get("/scope", keycloak.protect(), (req, res) => {
	const tokenContent = req.kauth.grant.access_token.content;
	const scopes = tokenContent.scope.split(" ");

	if (scopes.includes("app-payment-scope")) {
		res.send("This is a protected route user with the correct scope");
	} else {
		res.status(403).send("Forbidden: Insufficient scope");
	}
});

app.get(
	"/scopeenforced",
	keycloak.enforcer("scope:app-payment-scope"),
	(req, res) => {
		res.send("This is a protected route user with the correct scope");
	},
);

app.listen(8000, () => {
	console.log("App listening on port 8000");
});
