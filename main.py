# -*- coding: utf-8 -*-

from base64 import b64encode
from base64 import b64decode
import hashlib
import os
import Crypto
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
import datetime
from OpenSSL import crypto
from pymongo import MongoClient
import urllib.parse

class Database:
    def __init__(self):
        username = urllib.parse.quote_plus('user')
        password = urllib.parse.quote_plus('v4s_ed1-20192')

        self.client = MongoClient('192.168.96.38',
                      27017,
                      username=username,
                      password=password,
                      authSource='vas',
                      authMechanism='SCRAM-SHA-256')

database = Database()
class Usuario:
    
    def __init__(self, id, voto):
        self.__id = id
        self.__voto = voto
        
    def getId(self):
        return self.__id
    def setId(self, id):
        self.__id = id
    def isVoto(self):
        return self.__voto
    def setVoto(self, voto):
        self.__voto = voto

class DNI:
    
    def __init__(self, valor, disponible):
        self.__valor = valor
        self.__disponible = disponible
        
    def getValor(self):
        return self.__valor
    def setValor(self, valor):
        self.__valor = valor
    def isDisponible(self):
        return self.__disponible
    def setDisponible(self, disponible):
        self.__disponible = disponible
    def __str__(self):
        return self.__valor

class Candidato:
    
    def __init__(self, nombre, numeroVotos, partido, indice):
        self.__nombre = nombre
        self.__numeroVotos = numeroVotos
        self.__partido = partido
        self.__indice = indice
    
    def getNombre(self):
        return self.__nombre
    def setNombre(self, nombre):
        self.__nombre = nombre
    def getNumeroVotos(self):
        return self.__numeroVotos
    def setNumeroVotos(self, numeroVotos):
        self.__numeroVotos = numeroVotos
    def getPartido(self):
        return self.__partido
    def setPartido(self, partido):
        self.__partido = partido
    def getIndice(self):
        return self.__indice
    def setIndice(self, indice):
        self.__indice = indice
    def __str__(self):
        return self.__nombre+" "+self.__partido

class Registraduria:
    def __init__(self):
        
        # USUARIOS REGISTRADOS -------------------------------------------------
        
        usu1 = Usuario("1234086575", False)
        usu2 = Usuario("1143975309", False)
        usu3 = Usuario("1013679139", False)
        usu4 = Usuario("1152455884", False)
        usu5 = Usuario("1020832539", False)
        usu6 = Usuario("1020828212", False)
        usu7 = Usuario("1234089174", False)
        usu8 = Usuario("1037663762", False)
        usu9 = Usuario("1140890190", False)
        usu10 = Usuario("1000415031", False)
        usu11 = Usuario("1140863385", False)
        usu12 = Usuario("1136887785", False)
        usu13 = Usuario("1144095730", False)
        usu14 = Usuario("1020810599", False)
        usu15 = Usuario("1144046894", False)
        usuarios=[]
        usuarios.append(usu1)
        usuarios.append(usu2)
        usuarios.append(usu3)
        usuarios.append(usu4)
        usuarios.append(usu5)
        usuarios.append(usu6)
        usuarios.append(usu7)
        usuarios.append(usu8)
        usuarios.append(usu9)
        usuarios.append(usu10)
        usuarios.append(usu11)
        usuarios.append(usu12)
        usuarios.append(usu13)
        usuarios.append(usu14)
        usuarios.append(usu15)
        self.__usuarios = usuarios
        
        c1 = Candidato("Francisco Vega", 0, "EDI-20192",1)
        c2 = Candidato("Estiven Landazuri", 0, "EDI-20192",2)
        c3 = Candidato("Andres Alvarez", 0, "EDI-20192",3)
        c4 = Candidato("Evelyn Zuluaga", 0, "EDI-20192",4)
        c5 = Candidato("Hugo Santiago", 0, "EDI-20192",5)
        c6 = Candidato("Christian Florez", 0, "EDI-20192",6)
        c7 = Candidato("Daniel Marquez", 0, "EDI-20192",7)
        c8 = Candidato("Kevin Gonzalez", 0, "EDI-20192",8)
        c9 = Candidato("Mariana Padilla", 0, "EDI-20192",9)
        c10 = Candidato("Duvan Antivar", 0, "EDI-20192",10)
        c11 = Candidato("Cristian Gutierrez", 0, "EDI-20192",11)
        c12 = Candidato("Valentina Gil", 0, "EDI-20192",12)
        c13 = Candidato("Camilo Charria", 0, "EDI-20192",13)
        c14 = Candidato("Veronica Calle", 0, "EDI-20192",14)
        c15 = Candidato("James Montealegre", 0, "EDI-20192",15)
        candidatos = []
        candidatos.append(c1)
        candidatos.append(c2)
        candidatos.append(c3)
        candidatos.append(c4)
        candidatos.append(c5)
        candidatos.append(c6)
        candidatos.append(c7)
        candidatos.append(c8)
        candidatos.append(c9)
        candidatos.append(c10)
        candidatos.append(c11)
        candidatos.append(c12)
        candidatos.append(c13)
        candidatos.append(c14)
        candidatos.append(c15)
        self.__candidatos = candidatos
        
        #-----------------------------------------------------------------------

    def getUsuarios(self):
        return self.__usuarios
    def getCandidatos(self):
        return self.__candidatos
    
# --------------------------- FUNCIONES ----------------------------------------

registraduria = Registraduria()

# VALIDACION DE IDENTIDAD ------------------------------------------------------

def esCiudadano(id):
    """ Verifica si el id ingresado pertenece a un ciudadano

    Args:
        id (int): Identificacion a verificar

    Returns:
        bool: Boolean que indica si es ciudadano o no
    """
    idRegistraduria = 0
    encontro = False
    usuarios = registraduria.getUsuarios()
    for i in usuarios:
        usuario = i
        idRegistraduria = usuario.getId()
        if(idRegistraduria == id):
            usuario.setVoto(True)
            encontro = True
    return encontro

# GENERACION DE QR -------------------------------------------------------------

def generar_QR():
    """ Genera la hora maxima habilitada para votar
        Args:
        
        Returns:
            tuple: Hora maxima con el formato (MM, DD, AAAA, HH, MM, SS)
    """
    x = datetime.datetime.now()
    dia = x.day
    mes = x.month
    anio = x.year
    hora = x.hour
    minutos = x.minute
    seg = x.second
    if minutos >= 59:
        minutos = 0
        min = minutos + 3
    else: 
        min = minutos + 3
    hora_generada = mes,dia,anio,hora,min,seg
    return hora_generada

def firmar(msg, p12):
    """ Firma un mensaje con el archivo p12 indicado
        Args:
            msg (str): Cadena a firmar
            p12 (str): Cadena de ubicacion del archivo p12 con el que se firmara msg
        
        Returns:
            str: Una cadena con el mensaje y la firma concatenados
    """
    p12 = crypto.load_pkcs12(open(p12, "rb").read(), "12345678")
    private_key = p12.get_privatekey()
    sign = crypto.sign(private_key, msg, "sha384")
    stringQR = "".join( chr(x) for x in bytearray(sign) )
    return msg + stringQR

def verificar(msg, sign, p12):
    """ Verifica si el mensaje si es el que fue firmado con el archivo p12
        Args:
            msg (str): Cadena con el mensaje a verificar
            sign (bytes): Firma en formato bytes
        
        Returns:
            None: En caso de ser correcto retorna None, de lo contrario
                  se interrumpe el flujo con una excepcion
    """
    p12 = crypto.load_pkcs12(open(p12, "rb").read(), "12345678")
    certificate = p12.get_certificate()
    return crypto.verify(certificate, sign, msg, "sha384")

def cargar_qr(signed_message):
    """ Carga el valor del qr y la firma del mismo
        Args:
            signed_message (str): Cadena que contiene tanto el valor del qr como
                                  la firma
        
        Returns:
            tuple: Una tupla que contiene el mensaje como cadena y la firma como bytes
    """
    msg = signed_message[signed_message.find("("):signed_message.find(")")+1]
    pre_sign = signed_message[signed_message.find(")"):]
    pre_sign = pre_sign[1:]
    pre_sign2 = bytearray()

    for i in range(len(pre_sign)):
        pre_sign2+=bytes([ord(pre_sign[i])])
    sign = bytes(pre_sign2)

    return msg, sign

def cargar_votos(signed_message):
    """ Carga el valor del voto y la firma del mismo
        Args:
            signed_message (str): Cadena que contiene tanto el valor del voto como
                                  la firma
        
        Returns:
            tuple: Una tupla que contiene el mensaje como cadena y la firma como bytes
    """
    msg = signed_message[:signed_message.find("=")+1]
    pre_sign = signed_message[signed_message.find("="):]
    pre_sign = pre_sign[1:]
    pre_sign2 = bytearray()

    for i in range(len(pre_sign)):
        pre_sign2+=bytes([ord(pre_sign[i])])
    sign = bytes(pre_sign2)

    return msg, sign

def encrypt_vote(message):
    """ Encripcion simetrica con CBC del voto
        Args:
            message (str): Valor del voto en formato de cadena
        
        Returns:
            ct (str): Mensaje cifrado
            key (bytes): Clave de encripcion
            iv (str): Vector inicial de la encripcion
    """
    # Definir clave e initial_vector 
    key = os.urandom(32)
    iv = os.urandom(16)
    obj = AES.new(key, AES.MODE_CBC, iv)
    
    # Realizar padding
    length = 16 - (len(message) % 16)
    message = bytes(message, 'utf-8')
    message += bytes([length])*length
    
    # Encripcion, obtencion texto cifrado y vector inicial en base 64
    ct_bytes = obj.encrypt(message)
    iv = b64encode(obj.IV).decode('utf-8')
    ct = b64encode(ct_bytes).decode('utf-8')

    db = database.client.vas
    db.voto.insert_one({"voto": ct})
    db.clave.insert_one({"clave": key, "iv": iv})

    return ct, key, iv

def decrypt_vote(ct, key, iv):
    """ Desencripcion simetrica con CBC del voto
        Args:
            ct (str): Mensaje cifrado
            key (bytes): Clave de encripcion
            iv (str): Vector inicial de la encripcion
        
        Returns:
            message (str): Valor del voto en formato de cadena
            
    """
    # Decodificación de base 64
    ct = b64decode(ct)
    iv = b64decode(iv)

    # Desencripcion
    obj = AES.new(key, AES.MODE_CBC, iv)
    msg = obj.decrypt(ct)

    # ELiminacion de padding
    msg = msg[:-msg[-1]]

    return str(msg, 'utf-8')

def conteo():
    db = database.client.vas

    voto_db = db.voto
    clave_db = db.clave

    votos = []
    claves = []
    for voto in voto_db.find():
        votos.append(voto['voto'])
    
    for clave in clave_db.find():
        claves.append({"clave": clave["clave"], "iv": clave["iv"]})

    votos_decrypt = []
    for voto in votos:
        for clave in claves:
            try:
                voto_dc = decrypt_vote(voto, clave["clave"], clave["iv"])
                if voto_dc != '':
                    votos_decrypt.append(voto_dc)
            except:
                next
    
    voto_={"Petro": 0, "Duque": 0}

    for voto in votos_decrypt:
        if voto=="Voto por Petro":
            voto_["Petro"] = voto_["Petro"] + 1
        elif voto=="Voto por Duque":
            voto_["Duque"] = voto_["Duque"] + 1


    print(voto_)
conteo()