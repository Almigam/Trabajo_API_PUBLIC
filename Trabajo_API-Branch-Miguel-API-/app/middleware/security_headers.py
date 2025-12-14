# En este archivo, vamos a definir y gestionar las cabeceras de seguridad que vamos a añadir a todas las respuestas que emita la aplicacion. 
# Estas cabeceras son esenciales para reforzar la proteccion del servidor contra ataques del lado del el navegador, como la inyeccion de scripts, 
# exposicion innecesaria de metadatos, degradacion de protocolos seguros etc... 
# 
# A traves del codigo de este archivo, aplicamos politicas de seguridad, basadas en buenas practicas OWASP, incluyendo medidas como restricciones
# de permisos del navegador, X Frame Options etc.... 
# 
# A todo esto lo llamamos middleware, el cual nos permite interceptar, modificar y en general supervisar la respuesta, sin alterar el codigo
# de los endpoints

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

# En esta clase implementamos un middleware, que modifica todas las respuestas HTTP añadiendo cabeceras de seguridad, con el objetivo de reforzar
# la proteccion del cliente contra ataques comunes relacionados con el navegador

class SecurityHeadersMiddleware(BaseHTTPMiddleware): # Aqui tenemos el middleware, que intercepta respuestas para añadir cabeceras de seguridad
    
    async def dispatch(self, request: Request, call_next): # Mediante metodo, interceptamos la respuesta que genera el endpoint y añadimos 
                                                        # cabeceras de seguridad a la response 
                                        
# Para entender bien el flujo de este codigo, debemos entender dos cosas primero: 
# 
# El middleware que estamos aplicando para nuestra aplicacion, solo incluye cabeceras de seguridad para la respuesta que realiza el endpoint, sin 
# embargo, el middleware tiene la capacidad de hacer esto antes y despues de que la request pase por el endpoint, por esto mismo, los middleware
# envuelven al endpoint. EL flujo seria el siguente: 
# 
# request → middleware → request → securizada → call_next → endpoint → middleware → response securizada
# 
# sin embargo, en nuestro caso es asi: 
# 
# request → middleware → call_next → endpoint → middleware → response securizada
# porque nuestro middleware solo securiza la respuesta
# 
# Vemos que la request pasa por el middleware, y despues se ejecuta call_next, debido a que sino, la request no llegaria al endpoint. Una vez la 
# request llega al endpoint, y se genera la response, call_next "lleva" la response al middleware, para securizarla y finalmente entregarla al 
# cliente 
                                
        # Obtenemos la response, despues de que la request, sea procesada por el end point y genere la response, luego, gracias a call_next
        # hacemos que la response, vuelva al middleware para ser securizada
        response: Response = await call_next(request) 
        
        # Una vez que la response vuelve al middleware, este añade las cabeceras de seguridad. Starlette incluirá estas cabeceras en la respuesta 
        # HTTP y será el navegador quien las interprete y aplique las políticas que se indican.

        # Con esta cabecerá prevenimos el clickjacking. Sin esta cabecera, un atacante podría crear una pagina falsa invisible "encima" de nuestra 
        # aplicacion, donde el usuario crea que está haciendo clic en una cosa, pero realmente, esta haciendo clic en otra por la accion del 
        # tacante. Para impedir esto, lo que hace la cabecera es que nuestra aplicacion no pueda aparecer dentro de iframes
        response.headers["X-Frame-Options"] = "DENY"
        
        # Evitamos que el navegador intente adivinar el tipo de MIME y que respete el tipo que se declaró al salir del servidor, sin esta cabecera
        # si un atacante cambiase imaginemos, una foto por un script, y el navegador, al ver que es un ejecutable, podria ejecutarlo.
        response.headers["X-Content-Type-Options"] = "nosniff"
        
        # Es una proteccion basica contra el Cross Site Scriptring para navegadores antiguos
        response.headers["X-XSS-Protection"] = "1; mode=block"
        
        # Forzar HTTPS (solo en producción) añadiendo Strict Transport Security
        if request.url.scheme == "https":
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains"
            ) # Declaramos que la "edad" o duracion maxima tiene que ser de 31536000 segundos (1 año) y que tambien efecte a subdominios
        
        # Controlar referrer para limitar la exposición de URLs que no queremos que sean expuestas, mas especificamente cuando pasamos desde
        # https a http
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        
        # Deshabilitar funcionalidades que no interesan (mediante = () los deshabilitamos)
        response.headers["Permissions-Policy"] = (
            "geolocation=(), microphone=(), camera=(), payment=(), usb=()"
        )
        
        # Dfinimos la politica de seguridad de contenido (Content Security Policy)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; " # solo permite cargar recursos (como scripts, estilos, imágenes) desde el mismo origen que el de la aplicacion
            "script-src 'self' 'unsafe-inline'; " # Permite ejecutar JavaScript solo desde el mismo origen que el de la aplicacion
            "style-src 'self' 'unsafe-inline'; " # Permite cargar hojas de estilo CSS desde el mismo origen que el de la pagina
            "img-src 'self' data: https:; " # Permite cargar imágenes desde el mismo origen que el de la aplicacion, datos embebidos y desde  
                                            # cualquier sitio que use HTTPS
            "font-src 'self'; " # Permite cargar fuentes solo desde el mismo origen que el de la aplicacion
            "connect-src 'self'; " # limita las conexiones de scripts solo al origen de la pagina
            "frame-ancestors 'none'; " # Impide que la página se muestre dentro de un iframe
            "base-uri 'self'; " # Obliga a que la etiqueta <base> solo pueda apuntar al mismo origen, evitando redirecciones maliciosas.
            "form-action 'self'" # Permite que los formularios solo envíen datos al mismo origen que el de la aplicacion
        )
        
        # Elimina las cabeceras que revelan tecnologia del servidor
        response.headers.pop("Server", None)
        
        return response   