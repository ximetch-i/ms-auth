# ms-auth

## Estructura de Lambdas (2)

Una Lambda atiende varios endpoints: el codigo elige la funcion segun la ruta (`requestPath` de API Gateway).

- `auth.py` -> Lambda **Auth**: /auth/login, /auth/crear-usuario
- `validar_token.py` -> ValidarTokenAcceso (sin ruta HTTP, la invocan las Lambdas de los 6 micros).

`comun.py` es codigo compartido (token, respuestas, helpers), no es una Lambda.
