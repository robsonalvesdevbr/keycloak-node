const session = require("express-session");
const Keycloak = require("keycloak-connect");
const express = require("express");
const cors = require("cors");
const app = express();

const memoryStore = new session.MemoryStore();

app.use(
	session({
		secret: "keycloak",
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

app.use(cors())

const nonProtectedRoutes = ["/logoff", "/callbacks"];

function checkPaymentScope(req, res, next) {
	keycloak.protect()(req, res, (error) => {
		if (error) return res.status(401).json({ error: "Unauthorized" });

		if (nonProtectedRoutes.includes(req.path)) {
			return next();
		}

		const token = req.kauth.grant.access_token;
		const scopes = token.content.scope || "";
		const roles = token.content.realm_access?.roles || []; //

		if (scopes.split(" ").includes("app-payment-scope")) {
			return next();
		}

		return res
			.status(403)
			.json({ error: "Forbidden - Missing required scope" });
	});
}

// Aplica o middleware global
app.use(checkPaymentScope);

// Middleware para verificar o scope app-payment-scope
function checkPaymentScopeRoute(req, res, next) {
	// Primeiro verifica se o token é válido
	keycloak.protect()(req, res, (error) => {
		if (error) {
			return res.status(401).json({ error: "Unauthorized" });
		}

		const token = req.kauth.grant.access_token;
		const scopes = token.content.scope || "";
		const roles = token.content.realm_access?.roles || []; //

		if (scopes.split(" ").includes("app-payment-scope")) {
			return next();
		}

		// Scope não encontrado
		return res
			.status(403)
			.json({ error: "Forbidden - Missing required scope" });
	});
}

app.get("/checkscoperoute", checkPaymentScopeRoute, (req, res) => {
	res.json({
		message: "Rota protegida!",
		required: "app-payment-scope",
		middleware: checkPaymentScopeRoute.name,
		path: req.path,
		scopes: req.kauth.grant.access_token.content.scope.split(" "),
	});
});

app.get("/checkprotect", keycloak.protect(), (req, res) => {
	res.json({
		message: "Rota protegida!",
		required: "app-payment-scope",
		middleware: checkPaymentScope.name,
		path: req.path,
		scopes: req.kauth.grant.access_token.content.scope.split(" "),
	});
});

app.get("/checkroleuser", keycloak.protect("realm:user"), (req, res) => {
	res.json({
		message: "Rota protegida!",
		required: "app-payment-scope",
		middleware: checkPaymentScope.name,
		path: req.path,
		scopes: req.kauth.grant.access_token.content.scope.split(" "),
		roles: req.kauth.grant.access_token.content.realm_access.roles,
	});
});

app.get("/checkroleadmin", keycloak.protect("realm:admin"), (req, res) => {
	res.json({
		message: "Rota protegida!",
		required: "app-payment-scope",
		middleware: checkPaymentScope.name,
		path: req.path,
		scopes: req.kauth.grant.access_token.content.scope.split(" "),
		roles: req.kauth.grant.access_token.content.realm_access.roles,
	});
});

app.get("/checkroles", keycloak.protect(["realm:user", "realm:admin"]), (req, res) => {
	res.json({
		message: "Rota protegida!",
		required: "app-payment-scope",
		middleware: checkPaymentScope.name,
		path: req.path,
		scopes: req.kauth.grant.access_token.content.scope.split(" "),
		roles: req.kauth.grant.access_token.content.realm_access.roles,
	});
});

app.get("/checkscopes", keycloak.protect(), (req, res) => {
	res.json({
		message: "Rota protegida!",
		required: "app-payment-scope",
		middleware: checkPaymentScope.name,
		path: req.path,
		scopes: req.kauth.grant.access_token.content.scope.split(" "),
		roles: req.kauth.grant.access_token.content.realm_access.roles,
	});
});

app.get("/logout", (req, res) => {
	keycloak.logout()(req, res);
});

app.listen(8000, () => {
	console.log("App listening on port 8000");
});
