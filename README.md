# backup-system
Esto es una práctica de cuarto curso de Ingeniería Informática en la UA, sobre Estrategias de Seguridad.

## Explicación
La práctica consiste en hacer un sistema de copias de seguridad que sea cifrado, y sea totalmente seguro, indescifrable para alguien que no conozca las claves.

### Notas de cifrado
- AES: Es usado para cifrar los archivos antes de subirlo al servidor, para conocimiento 0 del servidor.
- RSA: Es usado para cifrar las claves de cifrado (simétrico) de los archivos, ya que también se envían al servidor, y es conocimiento 0.
- TLS: Es usado para establecer comunicación mediante HTTP con el servidor de forma segura, evitando que algún atacante MITD intercepte mensajes en texto claro.
- SHA: Es usado para la expansión de la clave, cuando un usuario introduce su clave, se calcula su hash y la primera mitad del hash, se utiliza para enviar la clave privada cifrada al servidor, porque si la tuviese podría descifrar las claves (simétricas) de los ficheros y por lo tanto descifrar los ficheros. La segunda mitad del hash se usa para autenticarse en el servidor.

### Periodicidad
Además la práctica pide que un usuario pueda hacer copias de seguridad periódicas, esto lo hace el cliente y lo lógico es que con el cliente cerrado se sigan haciendo, pero esto depende del Sistema Operativo y no es el objetivo final de la práctica, por lo que simplemente hemos implementado que sólo funcione con el cliente abierto.
Sin embargo, tiene persistencia, es decir que si cierras el cliente pero tienes copias de seguridad cada hora, cuando la abras seguirán existiendo estas periodicidades.

## Lenguajes
La práctica ha sido desarrollada en su mayoría en el lenguaje **Go**, a excepción de la interfaz que está hecha en **HTML con CSS y JS**, gracias a la librería de Lorca, que permite usar las Chrome-devs para hacer interfaces.

### Go
Se usa en la mayoría de la aplicación ya que está presente en la lógica del backend del cliente (hilos de copias de seguridad, cifrado y descifrado, compresión y descompresión, etc.), y en todo el servidor.

### HTML y CSS
El HTML se usa para darle una estructura a la interfaz, y el CSS para darle estilo (color, etc.).

### JavaScript
También tiene una parte de lógica, para no permitirle al usuario realizar acciones no válidas (como utilizar una contraseña poco segura), pero en su mayoría es para transformar los datos recibidos del servidor a algo legible por un usuario.
