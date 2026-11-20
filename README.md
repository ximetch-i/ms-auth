# ms-auth

## Estructura de Lambdas (1)

Una Lambda atiende varios endpoints: el codigo elige la funcion segun la ruta (`requestPath` de API Gateway).

- `auth.py` -> Lambda **Auth**: /auth/login, /auth/crear-usuario

`comun.py` es codigo compartido (token, respuestas, helpers), no es una Lambda.
