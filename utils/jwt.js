const jwt = require("jsonwebtoken");

const token =
  "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICI3SGxxX1BmU2pDVjlZZUM3Yy1LZGRCVTZPQ0czVXMwN2tOb0ZxTkhsbjhNIn0.eyJleHAiOjE3NDQ4MDc2MTUsImlhdCI6MTc0NDgwNzMxNSwiYXV0aF90aW1lIjoxNzQ0ODA2ODI2LCJqdGkiOiJvbnJ0YWM6OTEwNTE2ZTktYTNlMy00ZmM5LWJiNTEtNzg1Yjg0OWUwNmU5IiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL3JlYWxtcy9lY29tbWVyY2UiLCJzdWIiOiJhNTY4NTE0NS02OGVjLTQxOGMtOGUyMy01YWE4NmEyZWRiZWQiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJhcHAtcGF5bWVudC1jbGllbnQiLCJzaWQiOiJkNjdmMjRhYy0yODFjLTQ1MWQtYjljOC0wY2QyZjJkMjhjNTYiLCJhY3IiOiIwIiwiYWxsb3dlZC1vcmlnaW5zIjpbImh0dHA6Ly9sb2NhbGhvc3Q6ODAwMCJdLCJyZWFsbV9hY2Nlc3MiOnsicm9sZXMiOlsib2ZmbGluZV9hY2Nlc3MiLCJhcHAtcGF5bWVudC1yb2xlIiwidXNlciJdfSwic2NvcGUiOiJvcGVuaWQgZW1haWwgcHJvZmlsZSBhcHAtcGF5bWVudC1zY29wZSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJuYW1lIjoiUm9ic29uIEFsdmVzIiwicHJlZmVycmVkX3VzZXJuYW1lIjoicm9ic29uIiwiZ2l2ZW5fbmFtZSI6IlJvYnNvbiIsImZhbWlseV9uYW1lIjoiQWx2ZXMiLCJlbWFpbCI6InJvYnNvbkB0ZXN0dXNlci5jb20ifQ.IfI18bkpKdPU_boqkFWRTRZf96kQC2yvFxouTjQguW55VmQoctmxX6qkfJxSFd1W-4kJJjPwkdAciX7wqHZFYa-DlgIPaQiYSsDHCd8J7pt8YQQI-RmH_ZTkzKXb7NPgfcXm0v_2T89L4hDlDKXi1IXj8pqcP50vmRQVD0Tvyu5afiU-0sxjYYJ7HIaYa8GJVJFWllduAXDn3VhUKKHNUG1N2HcmT12eM9iqMg1OIvsJL9rDRBFmATxCJO7DUasULrGoiFzDpMl_03qlX3aUIJxosPHDYyad28q-S154XkIwJ1xb1t1nmoHeNupHGmzMdLIlEEF6naVO419Roar3Sg";
const decodedToken = jwt.decode(token, { complete: true });

console.log(decodedToken);
