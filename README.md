Proyecto realizado para cifrar y descifrar con una clave siemtrica AES256. 
Se realizará con ECB, ya que, si se usara CBC habría que incluir un vector IV, que omito por simplididad.
En este driver se centrará principalmente es 3 dispositivos con 2 operaciones:
El dispositivo 1:
	- La operación de lectura generará una clave AES de 256 bits aleatoria
	- La operación de escritura pasará una clave AES de 256 bits por escritura
El dispositivo 2:
	- La operación de lectura mostrará el mensaje cifrado, en caso de existir
	- La operación de escritura cifrará el mensaje que se le pase por escritura
El dispositivo 3:
	- La operación de lectura mostrará el mensaje descifrado, en caso de existir
	- La operación de escritura descifrará el mensaje que se le pase por escritura

