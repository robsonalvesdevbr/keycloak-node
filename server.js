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

const nonProtectedRoutes = ["/logoff", "/callbacks"];

function checkPaymentScope(req, res, next) {
	keycloak.protect()(req, res, (error) => {
		if (error) return res.status(401).json({ error: 'Unauthorized' });

		if (nonProtectedRoutes.includes(req.path)) {
			return next();
		}

		const token = req.kauth.grant.access_token;
		const scopes = token.content.scope || '';
		const roles = token.content.realm_access?.roles || []; //

		if (scopes.split(' ').includes('app-payment-scope')) {
			return next();
		}

		return res.status(403).json({ error: 'Forbidden - Missing required scope' });
	});
}

// Aplica o middleware global
app.use(checkPaymentScope);

// Middleware para verificar o scope app-payment-scope
function checkPaymentScopeRote(req, res, next) {
	// Primeiro verifica se o token é válido
	keycloak.protect()(req, res, (error) => {
		if (error) {
			return res.status(401).json({ error: 'Unauthorized' });
		}

		const token = req.kauth.grant.access_token;
		const scopes = token.content.scope || '';
		const roles = token.content.realm_access?.roles || []; //

		if (scopes.split(' ').includes('app-payment-scope')) {
			return next();
		}

		// Scope não encontrado
		return res.status(403).json({ error: 'Forbidden - Missing required scope' });
	});
}

app.get("/testuses", checkPaymentScopeRote, (req, res) => {
	res.send("This is a protected route user with the correct scope");
});

app.get("/complain", keycloak.protect(), (req, res) => {
	res.send("This is a protected route");
});

app.get("/user", keycloak.protect("realm:user"), (req, res) => {
	res.send("This is a protected route user");
});

app.get("/administrator", keycloak.protect("realm:admin"), (req, res) => {
	res.send("This is a protected route user");
});

app.get("/all", keycloak.protect(["realm:user", "realm:admin"]), (req, res) => {
	res.send("This is a protected route user");
});

app.get("/protected", keycloak.protect(), (req, res) => {
	const tokenContent = req.kauth.grant.access_token.content;
	const scope = tokenContent.scope;
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

app.get('/logout', (req, res) => {
	keycloak.logout()(req, res);
});

app.listen(8000, () => {
	console.log("App listening on port 8000");
});
